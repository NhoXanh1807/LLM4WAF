"""
RAG service for defense rule generation
With persistent vector store, auto-rebuild detection, and WAF-specific filtering
"""

import os
import json
import hashlib
from typing import List, Dict, Any, Optional
from sentence_transformers import CrossEncoder
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import TextLoader, PyPDFLoader, Docx2txtLoader
#from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


class CrossEncoderReranker:
    """Re-rank retrieved documents using cross-encoder"""
    
    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model = CrossEncoder(model_name, device="cuda")
    
    def rerank(self, query: str, documents: List[Document], top_k: int = 3) -> List[tuple]:
        """Re-rank documents based on relevance to query"""
        if not documents:
            return []
        
        pairs = [[query, doc.page_content] for doc in documents]
        scores = self.model.predict(pairs)
        
        doc_score_pairs = list(zip(documents, scores))
        doc_score_pairs.sort(key=lambda x: x[1], reverse=True)
        
        return doc_score_pairs[:top_k]


class DocumentIndexManager:
    """Manages document indexing and change detection"""
    
    def __init__(self, docs_folder: str, index_file: str = ".rag_index.json"):
        self.docs_folder = docs_folder
        self.index_file = os.path.join(docs_folder, index_file)
        self.current_index = {}
    
    def _compute_file_hash(self, filepath: str) -> str:
        """Compute MD5 hash of file content"""
        hasher = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Warning: Failed to hash {filepath}: {str(e)}")
            return ""
    
    def _scan_documents(self) -> Dict[str, Dict[str, Any]]:
        """Scan all documents and build index"""
        index = {}
        
        if not os.path.exists(self.docs_folder):
            return index
        
        data_types = ["Rules", "XSS", "SQLi"]
        waf_types = ["Cloudflare", "ModSecurity", "AWS", "Naxsi"]
        
        for data_type in data_types:
            folder_path = os.path.join(self.docs_folder, data_type)
            
            if not os.path.exists(folder_path):
                continue
            
            if data_type == "Rules":
                # Rules folder has WAF subfolders
                for waf_type in waf_types:
                    waf_folder_path = os.path.join(folder_path, waf_type)
                    
                    if not os.path.exists(waf_folder_path):
                        continue
                    
                    files = [f for f in os.listdir(waf_folder_path) 
                            if os.path.isfile(os.path.join(waf_folder_path, f))]
                    
                    for filename in files:
                        if not filename.endswith(('.txt', '.pdf', '.docx', '.md')):
                            continue
                        
                        file_path = os.path.join(waf_folder_path, filename)
                        stats = os.stat(file_path)
                        file_hash = self._compute_file_hash(file_path)
                        
                        index[file_path] = {
                            "filename": filename,
                            "data_type": data_type,
                            "waf_type": waf_type,
                            "size": stats.st_size,
                            "modified": stats.st_mtime,
                            "hash": file_hash
                        }
            else:
                # XSS and SQLi folders have no subfolders
                files = [f for f in os.listdir(folder_path) 
                        if os.path.isfile(os.path.join(folder_path, f))]
                
                for filename in files:
                    if not filename.endswith(('.txt', '.pdf', '.docx', '.md')):
                        continue
                    
                    file_path = os.path.join(folder_path, filename)
                    stats = os.stat(file_path)
                    file_hash = self._compute_file_hash(file_path)
                    
                    index[file_path] = {
                        "filename": filename,
                        "data_type": data_type,
                        "waf_type": "None",
                        "size": stats.st_size,
                        "modified": stats.st_mtime,
                        "hash": file_hash
                    }
        
        return index
    
    def load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load saved index from disk"""
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load index: {str(e)}")
        return {}
    
    def save_index(self, index: Dict[str, Dict[str, Any]]):
        """Save index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save index: {str(e)}")
    
    def needs_rebuild(self) -> tuple[bool, str]:
        """
        Check if vector store needs rebuild
        
        Returns:
            (needs_rebuild: bool, reason: str)
        """
        old_index = self.load_index()
        new_index = self._scan_documents()
        
        self.current_index = new_index
        
        if not old_index:
            return True, "No previous index found"
        
        added = set(new_index.keys()) - set(old_index.keys())
        if added:
            return True, f"Added {len(added)} new file(s)"
        
        removed = set(old_index.keys()) - set(new_index.keys())
        if removed:
            return True, f"Removed {len(removed)} file(s)"
        
        modified = []
        for filepath in new_index.keys():
            if filepath in old_index:
                if new_index[filepath]["hash"] != old_index[filepath]["hash"]:
                    modified.append(filepath)
        
        if modified:
            return True, f"Modified {len(modified)} file(s)"
        
        return False, "No changes detected"
    
    def save_current_index(self):
        """Save current index to disk"""
        self.save_index(self.current_index)


class RAGDefenseService:
    """
    RAG-enhanced defense service with persistent vector store and WAF-specific filtering
    """
    
    def __init__(self, docs_folder: str = "./docs/", 
                vector_store_path: str = "./vector_store/",
                enable_rag: bool = True,
                force_rebuild: bool = False):
        """
        Initialize RAG service
        
        Args:
            docs_folder: Path to documents folder
            vector_store_path: Path to save/load vector store
            enable_rag: Whether to enable RAG
            force_rebuild: Force rebuild vector store
        """
        self.enable_rag = enable_rag
        self.docs_folder = docs_folder
        self.vector_store_path = vector_store_path
        self.vector_store = None
        self.retriever = None
        self.reranker = None
        self.index_manager = DocumentIndexManager(docs_folder)
        
        if self.enable_rag:
            self._initialize_rag(force_rebuild)
    
    def _initialize_rag(self, force_rebuild: bool = False):
        """Initialize all RAG components"""
        print("Initializing RAG service...")
        
        try:
            needs_rebuild, reason = self.index_manager.needs_rebuild()
            
            if force_rebuild:
                print("Force rebuild requested")
                needs_rebuild = True
                reason = "Force rebuild"
            
            if not needs_rebuild and os.path.exists(self.vector_store_path):
                print(f"No changes detected - loading existing vector store...")
                self._load_vector_store()
            else:
                print(f"Rebuild required: {reason}")
                self._build_vector_store()
            
            print("[4/4] Loading re-ranker...")
            self.reranker = CrossEncoderReranker()
            print("      Re-ranker ready")
            
            print("RAG service initialized successfully\n")
            
        except Exception as e:
            print(f"Error: Failed to initialize RAG: {str(e)}")
            self.enable_rag = False
    
    def _load_vector_store(self):
        """Load existing vector store from disk"""
        try:
            print("[1/4] Loading embeddings model...")
            embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-mpnet-base-v2",
                model_kwargs={"device": "cuda"}
            )
            print("      Embeddings ready")
            
            print("[2/4] Loading vector store from disk...")
            self.vector_store = FAISS.load_local(
                self.vector_store_path, 
                embeddings,
                allow_dangerous_deserialization=True
            )
            print("      Vector store loaded")
            
            print("[3/4] Setting up retriever...")
            self.retriever = self.vector_store.as_retriever(search_kwargs={"k": 10})
            print("      Retriever ready")
            
        except Exception as e:
            print(f"Warning: Failed to load vector store: {str(e)}")
            print("Rebuilding from scratch...")
            self._build_vector_store()
    
    def _build_vector_store(self):
        """Build new vector store from documents"""
        print("[1/4] Loading documents...")
        all_docs = self._load_documents()
        if not all_docs:
            print("Warning: No documents loaded, RAG will be disabled")
            self.enable_rag = False
            return
        print(f"      Loaded {len(all_docs)} documents")
        
        print("[2/4] Chunking documents...")
        chunks = self._chunk_documents(all_docs)
        print(f"      Created {len(chunks)} chunks")
        
        print("[3/4] Creating vector store...")
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-mpnet-base-v2",
            model_kwargs={"device": "cuda"}
        )
        
        self.vector_store = FAISS.from_documents(chunks, embeddings)
        
        print("      Saving vector store to disk...")
        os.makedirs(self.vector_store_path, exist_ok=True)
        self.vector_store.save_local(self.vector_store_path)
        
        self.index_manager.save_current_index()
        
        print("      Vector store ready and saved")
        
        self.retriever = self.vector_store.as_retriever(search_kwargs={"k": 10})
    
    def _load_documents(self) -> List[Document]:
        """Load documents from structured folders"""
        all_docs = []
        
        if not os.path.exists(self.docs_folder):
            print(f"Warning: Documents folder not found: {self.docs_folder}")
            return all_docs
        
        data_types = ["Rules", "XSS", "SQLi"]
        waf_types = ["Cloudflare", "ModSecurity", "AWS", "Naxsi"]
        
        for data_type in data_types:
            folder_path = os.path.join(self.docs_folder, data_type)
            
            if not os.path.exists(folder_path):
                continue
            
            if data_type == "Rules":
                # Rules folder has WAF subfolders
                for waf_type in waf_types:
                    waf_folder_path = os.path.join(folder_path, waf_type)
                    
                    if not os.path.exists(waf_folder_path):
                        continue
                    
                    files = [f for f in os.listdir(waf_folder_path) 
                            if os.path.isfile(os.path.join(waf_folder_path, f))]
                    
                    for filename in files:
                        file_path = os.path.join(waf_folder_path, filename)
                        
                        try:
                            if filename.endswith(".txt") or filename.endswith(".md"):
                                loader = TextLoader(file_path, encoding="utf-8")
                                file_type = "txt" if filename.endswith(".txt") else "md"
                            elif filename.endswith(".pdf"):
                                loader = PyPDFLoader(file_path)
                                file_type = "pdf"
                            elif filename.endswith(".docx"):
                                loader = Docx2txtLoader(file_path)
                                file_type = "docx"
                            else:
                                continue
                            
                            docs = loader.load()
                            
                            for doc in docs:
                                doc.metadata = {
                                    "source": filename,
                                    "data_type": data_type,
                                    "waf_type": waf_type,
                                    "file_type": file_type,
                                    "file_path": file_path
                                }
                            
                            all_docs.extend(docs)
                            
                        except Exception as e:
                            print(f"Warning: Failed to load {filename}: {str(e)}")
                            continue
            else:
                # XSS and SQLi folders - no subfolders
                files = [f for f in os.listdir(folder_path) 
                        if os.path.isfile(os.path.join(folder_path, f))]
                
                for filename in files:
                    file_path = os.path.join(folder_path, filename)
                    
                    try:
                        if filename.endswith(".txt") or filename.endswith(".md"):
                            loader = TextLoader(file_path, encoding="utf-8")
                            file_type = "txt" if filename.endswith(".txt") else "md"
                        elif filename.endswith(".pdf"):
                            loader = PyPDFLoader(file_path)
                            file_type = "pdf"
                        elif filename.endswith(".docx"):
                            loader = Docx2txtLoader(file_path)
                            file_type = "docx"
                        else:
                            continue
                        
                        docs = loader.load()
                        
                        for doc in docs:
                            doc.metadata = {
                                "source": filename,
                                "data_type": data_type,
                                "waf_type": "None",
                                "file_type": file_type,
                                "file_path": file_path
                            }
                        
                        all_docs.extend(docs)
                        
                    except Exception as e:
                        print(f"Warning: Failed to load {filename}: {str(e)}")
                        continue
        
        return all_docs
    
    def _chunk_documents(self, documents: List[Document]) -> List[Document]:
        """Chunk documents using fixed-size chunking"""
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        chunks = []
        
        for doc in documents:
            try:
                splits = splitter.split_text(doc.page_content)
                
                for i, split in enumerate(splits):
                    chunk = Document(
                        page_content=split,
                        metadata={
                            **doc.metadata,
                            "chunk_id": i,
                            "total_chunks": len(splits)
                        }
                    )
                    chunks.append(chunk)
            
            except Exception as e:
                print(f"Warning: Failed to chunk {doc.metadata.get('source')}: {str(e)}")
                continue
        
        return chunks
    
    def _generate_query_variants(self, attack_type: str, waf_info: dict, 
                                bypassed_payloads: list) -> List[str]:
        """Generate multiple query variants for multi-query retrieval"""
        queries = []
        
        attack_name = "XSS" if attack_type == "XSS" else "SQL injection"
        queries.append(f"{attack_name} defense strategies and prevention")
        
        if waf_info:
            waf_name = waf_info.get("waf", "")
            if waf_name:
                queries.append(f"{waf_name} {attack_name} protection rules")
        
        if bypassed_payloads:
            sample_payload = str(bypassed_payloads[0])[:100].lower()
            
            if "script" in sample_payload or "onerror" in sample_payload:
                queries.append("XSS bypass techniques and mitigation")
            elif "union" in sample_payload or "select" in sample_payload:
                queries.append("SQL injection union-based attack prevention")
            elif "or" in sample_payload and "=" in sample_payload:
                queries.append("SQL injection boolean-based blind attack defense")
            else:
                queries.append(f"{attack_name} bypass techniques")
        
        queries.append(f"security rules best practices {attack_name}")
        
        return queries
    
    def _extract_waf_name(self, waf_info: dict) -> Optional[str]:
        """Extract WAF name from waf_info and map to WAF_type"""
        if not waf_info:
            return None
        
        waf_name = waf_info.get("waf", "").lower()
        
        # Map WAF names to WAF_type
        waf_mapping = {
            "cloudflare": "Cloudflare",
            "modsecurity": "ModSecurity",
            "mod_security": "ModSecurity",
            "aws": "AWS",
            "aws waf": "AWS",
            "naxsi": "Naxsi"
        }
        
        for key, value in waf_mapping.items():
            if key in waf_name:
                return value
        
        return None
    
    def get_relevant_context(self, attack_type: str, waf_info: dict, 
                        bypassed_payloads: list, 
                        initial_k: int = 8,
                        final_k: int = 3,
                        filter_rules_only: bool = True) -> Dict[str, Any]:
        """
        Retrieve relevant context from knowledge base using multi-query retrieval
        
        Args:
            attack_type: Type of attack (e.g., "XSS", "SQLI")
            waf_info: WAF information dict
            bypassed_payloads: List of payloads that bypassed WAF
            initial_k: Number of documents to retrieve per query
            final_k: Number of documents after re-ranking
            filter_rules_only: If True, prioritize Rules documents
        
        Returns:
            Dict containing context and metadata
        """
        if not self.enable_rag:
            return {
                "context": "",
                "sources": [],
                "rag_enabled": False
            }
        
        try:
            queries = self._generate_query_variants(attack_type, waf_info, bypassed_payloads)
            
            all_retrieved_docs = []
            seen_contents = set()
            
            self.retriever.search_kwargs["k"] = initial_k
            
            for query in queries:
                docs = self.retriever.invoke(query)
                
                for doc in docs:
                    content_hash = hash(doc.page_content[:200])
                    if content_hash not in seen_contents:
                        seen_contents.add(content_hash)
                        all_retrieved_docs.append(doc)
            
            if not all_retrieved_docs:
                return {
                    "context": "",
                    "sources": [],
                    "rag_enabled": True
                }
            
            # WAF-specific filtering
            waf_name = self._extract_waf_name(waf_info)
            
            if filter_rules_only:
                # Separate by data_type and waf_type
                waf_specific_docs = []
                rules_docs = []
                other_docs = []
                
                for doc in all_retrieved_docs:
                    doc_data_type = doc.metadata.get("data_type", "")
                    doc_waf_type = doc.metadata.get("waf_type", "None")
                    
                    if doc_data_type == "Rules" and waf_name and doc_waf_type == waf_name:
                        # WAF-specific rules (highest priority)
                        waf_specific_docs.append(doc)
                    elif doc_data_type == "Rules":
                        # General rules (medium priority)
                        rules_docs.append(doc)
                    else:
                        # XSS/SQLi docs (lower priority)
                        other_docs.append(doc)
                
                # Prioritize WAF-specific docs (at least 3 if available)
                if waf_specific_docs:
                    waf_count = min(len(waf_specific_docs), max(3, final_k // 2))
                    remaining = final_k - waf_count
                    
                    # Fill remaining slots with general rules and attack-specific
                    rules_count = min(len(rules_docs), remaining // 2)
                    other_count = remaining - rules_count
                    
                    filtered_docs = (waf_specific_docs[:waf_count] + 
                                rules_docs[:rules_count] + 
                                other_docs[:other_count])
                else:
                    # No WAF-specific docs, fall back to general filtering
                    if rules_docs:
                        rules_count = max(len(rules_docs), final_k // 2)
                        other_count = final_k - min(rules_count, len(rules_docs))
                        
                        filtered_docs = rules_docs[:rules_count] + other_docs[:other_count]
                    else:
                        filtered_docs = all_retrieved_docs
            else:
                filtered_docs = all_retrieved_docs
            
            # Re-rank all filtered documents
            primary_query = queries[0]
            reranked_results = self.reranker.rerank(primary_query, filtered_docs, top_k=final_k)
            reranked_docs = [doc for doc, score in reranked_results]
            rerank_scores = [score for doc, score in reranked_results]
            
            # Build context
            context_parts = []
            sources = []
            
            for i, (doc, score) in enumerate(zip(reranked_docs, rerank_scores)):
                context_parts.append(f"[Reference {i+1}]\n{doc.page_content}")
                sources.append({
                    "source": doc.metadata.get("source", "Unknown"),
                    "data_type": doc.metadata.get("data_type", "Unknown"),
                    "waf_type": doc.metadata.get("waf_type", "None"),
                    "relevance_score": f"{score:.3f}"
                })
            
            context = "\n\n".join(context_parts)
            
            return {
                "context": context,
                "sources": sources,
                "rag_enabled": True,
                "num_docs": len(reranked_docs),
                "num_queries": len(queries),
                "waf_filtered": waf_name is not None
            }
            
        except Exception as e:
            print(f"Error: Context retrieval failed: {str(e)}")
            return {
                "context": "",
                "sources": [],
                "rag_enabled": True,
                "error": str(e)
            }
    
    def enhance_defense_prompt(self, waf_info: dict, bypassed_payloads: list, 
            bypassed_instructions: list, 
            base_user_prompt: str,
            filter_rules_only: bool = True
        ) -> Dict[str, Any]:
        """
        Enhance defense generation prompt with RAG context
        
        Args:
            waf_info: WAF information
            bypassed_payloads: List of bypassed payloads
            bypassed_instructions: Instructions for each payload
            base_user_prompt: Original user prompt from get_blue_team_user_prompt
            filter_rules_only: Whether to prioritize Rules documents (default: True)
        
        Returns:
            Dict with enhanced prompt and metadata
        """
        attack_type = self._detect_attack_type(bypassed_payloads)
        
        rag_result = self.get_relevant_context(
            attack_type=attack_type,
            waf_info=waf_info,
            bypassed_payloads=bypassed_payloads,
            filter_rules_only=filter_rules_only
        )
        
        if not rag_result["context"]:
            return {
                "enhanced_prompt": base_user_prompt,
                "rag_context": "",
                "sources": [],
                "rag_used": False
            }
        
        enhanced_prompt = f"""{base_user_prompt}

---
**KNOWLEDGE BASE REFERENCES**

The following references from our security knowledge base may help inform your defense strategy:

{rag_result["context"]}

---

Please consider these references when generating defense rules, but prioritize the specific bypassed payloads mentioned above."""
        
        return {
            "enhanced_prompt": enhanced_prompt,
            "rag_context": rag_result["context"],
            "sources": rag_result["sources"],
            "rag_used": True,
            "num_docs": rag_result.get("num_docs", 0),
            "num_queries": rag_result.get("num_queries", 0),
            "waf_filtered": rag_result.get("waf_filtered", False)
        }
    
    def _detect_attack_type(self, payloads: list) -> str:
        """Detect attack type from payloads"""
        payload_str = " ".join(str(p) for p in payloads).lower()
        
        if any(keyword in payload_str for keyword in ["script", "onerror", "onload", "alert", "xss"]):
            return "XSS"
        elif any(keyword in payload_str for keyword in ["union", "select", "or 1=1", "' or", "sql"]):
            return "SQLI"
        else:
            return "Unknown"
    
    def force_rebuild(self):
        """Force rebuild vector store"""
        print("\nForce rebuilding vector store...")
        self._build_vector_store()
        print("Rebuild complete\n")


# Singleton instance
_rag_service_instance = None


def get_rag_service(docs_folder: str = "./docs/", 
        vector_store_path: str = "./vector_store/",
        enable_rag: bool = True,
        force_rebuild: bool = False
    ) -> RAGDefenseService:
    """
    Get or create RAG service singleton
    
    Args:
        docs_folder: Path to documents folder
        vector_store_path: Path to save/load vector store
        enable_rag: Whether to enable RAG
        force_rebuild: Force rebuild vector store
    
    Returns:
        RAGDefenseService instance
    """
    global _rag_service_instance
    
    if _rag_service_instance is None or force_rebuild:
        _rag_service_instance = RAGDefenseService(
            docs_folder=docs_folder,
            vector_store_path=vector_store_path,
            enable_rag=enable_rag,
            force_rebuild=force_rebuild
        )
    
    return _rag_service_instance


def enhance_defense_generation(waf_info: dict, bypassed_payloads: list,
        bypassed_instructions: list,
        base_user_prompt: str,
        docs_folder: str = "./docs/",
        vector_store_path: str = "./vector_store/",
        enable_rag: bool = True,
        filter_rules_only: bool = True,
        force_rebuild: bool = False
    ) -> Dict[str, Any]:
    """
    Convenience function to enhance defense prompt with RAG
    
    Args:
        waf_info: WAF information
        bypassed_payloads: List of bypassed payloads
        bypassed_instructions: Instructions for bypassed payloads
        base_user_prompt: Base user prompt from get_blue_team_user_prompt
        docs_folder: Path to documents folder
        vector_store_path: Path to vector store
        enable_rag: Whether to enable RAG
        filter_rules_only: Whether to prioritize Rules documents (default: True)
        force_rebuild: Force rebuild vector store
    
    Returns:
        Dict with enhanced_prompt and metadata
    """
    rag_service = get_rag_service(
        docs_folder=docs_folder,
        vector_store_path=vector_store_path,
        enable_rag=enable_rag,
        force_rebuild=force_rebuild
    )
    
    return rag_service.enhance_defense_prompt(
        waf_info=waf_info,
        bypassed_payloads=bypassed_payloads,
        bypassed_instructions=bypassed_instructions,
        base_user_prompt=base_user_prompt,
        filter_rules_only=filter_rules_only
    )