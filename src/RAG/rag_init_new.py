# pip install langchain-community langchain-google-genai faiss-cpu python-dotenv
# pip install langchain docx2txt pypdf sentence-transformers
# pip install sentence-transformers transformers torch

import os
import logging
import time
import re
from datetime import datetime
from typing import List, Dict, Any, Tuple
from dotenv import load_dotenv
import numpy as np

# ==== SETUP LOGGING ====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rag_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==== LOAD ENV ====
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    logger.error("GOOGLE_API_KEY not found in environment variables")
    raise ValueError("Missing GOOGLE_API_KEY")

os.environ['GOOGLE_API_KEY'] = api_key

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import PromptTemplate
from langchain_community.document_loaders import TextLoader, PyPDFLoader, Docx2txtLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document
from sentence_transformers import SentenceTransformer, CrossEncoder

# ==== METRICS CLASS ====
class RAGMetrics:
    def __init__(self):
        self.metrics = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_latency": 0,
            "retrieval_times": [],
            "reranking_times": [],
            "llm_times": [],
            "validation_times": [],
            "documents_retrieved": [],
            "documents_after_reranking": []
        }
    
    def log_query(self, success: bool, latency: float, retrieval_time: float,
                   reranking_time: float, llm_time: float, validation_time: float,
                   num_docs: int, num_reranked: int):
        self.metrics["total_queries"] += 1
        if success:
            self.metrics["successful_queries"] += 1
        else:
            self.metrics["failed_queries"] += 1
        
        self.metrics["total_latency"] += latency
        self.metrics["retrieval_times"].append(retrieval_time)
        self.metrics["reranking_times"].append(reranking_time)
        self.metrics["llm_times"].append(llm_time)
        self.metrics["validation_times"].append(validation_time)
        self.metrics["documents_retrieved"].append(num_docs)
        self.metrics["documents_after_reranking"].append(num_reranked)
    
    def get_summary(self) -> Dict[str, Any]:
        total = self.metrics["total_queries"]
        if total == 0:
            return {"message": "No queries processed yet"}
        
        return {
            "total_queries": total,
            "success_rate": f"{(self.metrics['successful_queries'] / total) * 100:.2f}%",
            "avg_latency": f"{self.metrics['total_latency'] / total:.2f}s",
            "avg_retrieval_time": f"{sum(self.metrics['retrieval_times']) / len(self.metrics['retrieval_times']):.2f}s",
            "avg_reranking_time": f"{sum(self.metrics['reranking_times']) / len(self.metrics['reranking_times']):.2f}s",
            "avg_llm_time": f"{sum(self.metrics['llm_times']) / len(self.metrics['llm_times']):.2f}s",
            "avg_validation_time": f"{sum(self.metrics['validation_times']) / len(self.metrics['validation_times']):.2f}s",
            "avg_docs_retrieved": f"{sum(self.metrics['documents_retrieved']) / len(self.metrics['documents_retrieved']):.1f}",
            "avg_docs_after_reranking": f"{sum(self.metrics['documents_after_reranking']) / len(self.metrics['documents_after_reranking']):.1f}"
        }

metrics = RAGMetrics()

# ==== SEMANTIC CHUNKER ====
class SemanticChunker:
    """Semantic-based document chunking using sentence embeddings"""
    
    def __init__(self, embedding_model_name: str = "sentence-transformers/all-mpnet-base-v2",
                 similarity_threshold: float = 0.5, max_chunk_size: int = 1000):
        self.model = SentenceTransformer(embedding_model_name)
        self.similarity_threshold = similarity_threshold
        self.max_chunk_size = max_chunk_size
        logger.info(f"✓ Semantic chunker initialized with threshold={similarity_threshold}")
    
    def _split_into_sentences(self, text: str) -> List[str]:
        """Split text into sentences"""
        # Simple sentence splitting (can be enhanced with spaCy or NLTK)
        sentences = re.split(r'(?<=[.!?])\s+', text)
        return [s.strip() for s in sentences if s.strip()]
    
    def _calculate_similarities(self, embeddings: np.ndarray) -> List[float]:
        """Calculate cosine similarities between consecutive sentence embeddings"""
        similarities = []
        for i in range(len(embeddings) - 1):
            sim = np.dot(embeddings[i], embeddings[i + 1]) / (
                np.linalg.norm(embeddings[i]) * np.linalg.norm(embeddings[i + 1])
            )
            similarities.append(sim)
        return similarities
    
    def chunk_text(self, text: str) -> List[str]:
        """Chunk text based on semantic similarity"""
        sentences = self._split_into_sentences(text)
        
        if len(sentences) <= 1:
            return [text]
        
        # Get embeddings for all sentences
        embeddings = self.model.encode(sentences)
        
        # Calculate similarities
        similarities = self._calculate_similarities(embeddings)
        
        # Create chunks based on similarity drops
        chunks = []
        current_chunk = [sentences[0]]
        current_length = len(sentences[0])
        
        for i, (sentence, similarity) in enumerate(zip(sentences[1:], similarities)):
            # Check if we should start a new chunk
            if (similarity < self.similarity_threshold or 
                current_length + len(sentence) > self.max_chunk_size):
                # Save current chunk
                chunks.append(" ".join(current_chunk))
                current_chunk = [sentence]
                current_length = len(sentence)
            else:
                current_chunk.append(sentence)
                current_length += len(sentence)
        
        # Add the last chunk
        if current_chunk:
            chunks.append(" ".join(current_chunk))
        
        return chunks

# ==== RE-RANKER ====
class CrossEncoderReranker:
    """Re-rank retrieved documents using cross-encoder"""
    
    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model = CrossEncoder(model_name)
        logger.info(f"Cross-encoder re-ranker initialized: {model_name}")
    
    def rerank(self, query: str, documents: List[Document], top_k: int = 3) -> List[Tuple[Document, float]]:
        """Re-rank documents based on relevance to query"""
        if not documents:
            return []
        
        # Prepare pairs for cross-encoder
        pairs = [[query, doc.page_content] for doc in documents]
        
        # Get relevance scores
        scores = self.model.predict(pairs)
        
        # Sort by score (descending)
        doc_score_pairs = list(zip(documents, scores))
        doc_score_pairs.sort(key=lambda x: x[1], reverse=True)
        
        # Return top_k documents with scores
        return doc_score_pairs[:top_k]

# ==== OUTPUT VALIDATOR ====
class OutputValidator:
    """Validate LLM output for quality and relevance"""
    
    def __init__(self):
        self.min_answer_length = 10
        self.max_answer_length = 2000
        self.forbidden_phrases = [
            "i don't know",
            "i cannot answer",
            "as an ai",
            "i'm not sure"
        ]
    
    def validate(self, answer: str, question: str, context: str) -> Dict[str, Any]:
        """Validate the answer quality"""
        validation_start = time.time()
        
        issues = []
        score = 100.0
        
        # Check 1: Length validation
        if len(answer) < self.min_answer_length:
            issues.append("Answer too short")
            score -= 30
        elif len(answer) > self.max_answer_length:
            issues.append("Answer too long")
            score -= 10
        
        # Check 2: Forbidden phrases
        answer_lower = answer.lower()
        for phrase in self.forbidden_phrases:
            if phrase in answer_lower:
                issues.append(f"Contains forbidden phrase: '{phrase}'")
                score -= 20
        
        # Check 3: Check if answer is just repeating the question
        question_words = set(question.lower().split())
        answer_words = set(answer.lower().split())
        if len(question_words) > 3:
            overlap = len(question_words & answer_words) / len(question_words)
            if overlap > 0.8:
                issues.append("Answer mostly repeats the question")
                score -= 25
        
        # Check 4: Check if answer contains context information
        if len(context) > 50:
            # Simple check: does answer reference any content from context?
            context_words = set(context.lower().split())
            answer_context_overlap = len(answer_words & context_words)
            if answer_context_overlap < 3:
                issues.append("Answer may not be based on context")
                score -= 15
        
        # Check 5: Ensure answer is not empty or whitespace
        if not answer.strip():
            issues.append("Answer is empty")
            score = 0
        
        validation_time = time.time() - validation_start
        
        is_valid = score >= 50.0
        
        return {
            "is_valid": is_valid,
            "score": max(0, score),
            "issues": issues,
            "validation_time": validation_time
        }

# ==== LOAD DOCUMENTS WITH NEW FOLDER STRUCTURE ====
def load_documents_with_metadata(base_folder: str = "./docs/") -> List[Document]:
    """Load documents from structured folders (XSS, SQLi, Rules)"""
    all_docs = []
    
    if not os.path.exists(base_folder):
        logger.error(f"Base folder not found: {base_folder}")
        raise FileNotFoundError(f"Folder {base_folder} does not exist")
    
    # Expected subfolders
    data_types = ["XSS", "SQLi", "Rules"]
    
    for data_type in data_types:
        folder_path = os.path.join(base_folder, data_type)
        
        if not os.path.exists(folder_path):
            logger.warning(f"Subfolder not found: {folder_path}, skipping...")
            continue
        
        files = os.listdir(folder_path)
        logger.info(f"Processing {data_type} folder: {len(files)} files found")
        
        for filename in files:
            file_path = os.path.join(folder_path, filename)
            
            # Skip if not a file
            if not os.path.isfile(file_path):
                continue
            
            try:
                # Determine file type and loader
                if filename.endswith(".txt"):
                    loader = TextLoader(file_path, encoding="utf-8")
                    file_type = "txt"
                elif filename.endswith(".pdf"):
                    loader = PyPDFLoader(file_path)
                    file_type = "pdf"
                elif filename.endswith(".docx"):
                    loader = Docx2txtLoader(file_path)
                    file_type = "docx"
                else:
                    logger.warning(f" Skipping unsupported file: {filename}")
                    continue
                
                docs = loader.load()
                
                # Add simplified metadata
                for doc in docs:
                    doc.metadata = {
                        "source": filename,
                        "data_type": data_type,
                        "file_type": file_type,
                        "file_path": file_path
                    }
                
                all_docs.extend(docs)
                logger.info(f" Loaded {len(docs)} pages from {filename}")
                
            except Exception as e:
                logger.error(f" Failed to load {filename}: {str(e)}")
                continue
    
    logger.info(f" Total documents loaded: {len(all_docs)}")
    return all_docs

# ==== SEMANTIC CHUNK DOCUMENTS ====
def chunk_documents_semantically(documents: List[Document], 
                                  semantic_chunker: SemanticChunker) -> List[Document]:
    """Chunk documents using semantic chunking"""
    chunks = []
    
    for doc in documents:
        try:
            # Use semantic chunker
            semantic_chunks = semantic_chunker.chunk_text(doc.page_content)
            
            for i, chunk_text in enumerate(semantic_chunks):
                # Create new Document with metadata
                chunk = Document(
                    page_content=chunk_text,
                    metadata={
                        **doc.metadata,  # Preserve original metadata
                        "chunk_id": i,
                        "total_chunks": len(semantic_chunks)
                    }
                )
                chunks.append(chunk)
        
        except Exception as e:
            logger.error(f"Failed to chunk document from {doc.metadata.get('source')}: {str(e)}")
            continue
    
    logger.info(f"Created {len(chunks)} semantic chunks from {len(documents)} documents")
    return chunks

# ==== RAG QUERY WITH RE-RANKING AND VALIDATION ====
def query_rag(question: str, retriever, reranker: CrossEncoderReranker, 
              validator: OutputValidator, llm, prompt_template,
              initial_k: int = 10, final_k: int = 3) -> Dict[str, Any]:
    """Execute RAG query with re-ranking and output validation"""
    start_time = time.time()
    
    try:
        # Validate input
        if not question or len(question.strip()) < 5:
            logger.warning("Question too short or empty")
            return {
                "success": False,
                "error": "Question must be at least 5 characters",
                "answer": None
            }
        
        # Phase 1: Initial Retrieval
        retrieval_start = time.time()
        try:
            # Retrieve more documents initially for re-ranking
            retriever.search_kwargs["k"] = initial_k
            retrieved_docs = retriever.invoke(question)
        except Exception as e:
            logger.error(f"Retrieval failed: {str(e)}")
            return {
                "success": False,
                "error": f"Retrieval error: {str(e)}",
                "answer": None
            }
        retrieval_time = time.time() - retrieval_start
        
        if not retrieved_docs:
            logger.warning("No documents retrieved")
            return {
                "success": False,
                "error": "No relevant documents found",
                "answer": "I don't have enough information to answer this question."
            }
        
        logger.info(f"Retrieved {len(retrieved_docs)} initial documents")
        
        # Phase 2: Re-ranking
        reranking_start = time.time()
        try:
            reranked_results = reranker.rerank(question, retrieved_docs, top_k=final_k)
            reranked_docs = [doc for doc, score in reranked_results]
            rerank_scores = [score for doc, score in reranked_results]
        except Exception as e:
            logger.error(f"Re-ranking failed: {str(e)}")
            # Fallback to original retrieval
            reranked_docs = retrieved_docs[:final_k]
            rerank_scores = [0.0] * len(reranked_docs)
        reranking_time = time.time() - reranking_start
        
        logger.info(f" Re-ranked to top {len(reranked_docs)} documents")
        logger.info(f" Re-ranking scores: {[f'{s:.3f}' for s in rerank_scores]}")
        
        # Build context from re-ranked documents
        context_parts = []
        sources = []
        for i, (doc, score) in enumerate(zip(reranked_docs, rerank_scores)):
            context_parts.append(f"[Document {i+1} - Relevance: {score:.3f}]\n{doc.page_content}")
            sources.append({
                "source": doc.metadata.get("source", "Unknown"),
                "data_type": doc.metadata.get("data_type", "Unknown"),
                "file_type": doc.metadata.get("file_type", "Unknown"),
                "chunk_id": doc.metadata.get("chunk_id", "N/A"),
                "relevance_score": f"{score:.3f}"
            })
        
        context_text = "\n\n".join(context_parts)
        
        # Phase 3: LLM Generation
        llm_start = time.time()
        try:
            final_prompt = prompt_template.invoke({
                "context": context_text,
                "question": question
            })
            answer = llm.invoke(final_prompt)
            answer_text = answer.content
        except Exception as e:
            logger.error(f"LLM call failed: {str(e)}")
            return {
                "success": False,
                "error": f"LLM error: {str(e)}",
                "answer": None
            }
        llm_time = time.time() - llm_start
        
        # Phase 4: Output Validation
        validation_result = validator.validate(answer_text, question, context_text)
        
        if not validation_result["is_valid"]:
            logger.warning(f" Answer validation failed: {validation_result['issues']}")
        else:
            logger.info(f" Answer validation passed (score: {validation_result['score']:.1f})")
        
        # Calculate total latency
        total_latency = time.time() - start_time
        
        # Log metrics
        metrics.log_query(
            success=True,
            latency=total_latency,
            retrieval_time=retrieval_time,
            reranking_time=reranking_time,
            llm_time=llm_time,
            validation_time=validation_result["validation_time"],
            num_docs=len(retrieved_docs),
            num_reranked=len(reranked_docs)
        )
        
        # Log query details
        logger.info(f"""
         Query successful:
        - Question: {question[:100]}...
        - Retrieved docs: {len(retrieved_docs)} → Re-ranked: {len(reranked_docs)}
        - Retrieval time: {retrieval_time:.2f}s
        - Re-ranking time: {reranking_time:.2f}s
        - LLM time: {llm_time:.2f}s
        - Validation time: {validation_result['validation_time']:.2f}s
        - Total latency: {total_latency:.2f}s
        - Validation score: {validation_result['score']:.1f}/100
        """)
        
        return {
            "success": True,
            "answer": answer_text,
            "sources": sources,
            "num_docs_retrieved": len(retrieved_docs),
            "num_docs_reranked": len(reranked_docs),
            "retrieval_time": f"{retrieval_time:.2f}s",
            "reranking_time": f"{reranking_time:.2f}s",
            "llm_time": f"{llm_time:.2f}s",
            "validation_time": f"{validation_result['validation_time']:.2f}s",
            "total_latency": f"{total_latency:.2f}s",
            "validation": validation_result
        }
    
    except Exception as e:
        total_latency = time.time() - start_time
        logger.error(f"✗ Unexpected error: {str(e)}")
        
        metrics.log_query(
            success=False,
            latency=total_latency,
            retrieval_time=0,
            reranking_time=0,
            llm_time=0,
            validation_time=0,
            num_docs=0,
            num_reranked=0
        )
        
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "answer": None
        }

# ==== MAIN EXECUTION ====
def main():
    try:
        logger.info("=" * 70)
        logger.info(" Starting Enhanced RAG System")
        logger.info("=" * 70)
        
        # Load documents from new folder structure
        folder_path = "./docs/"
        all_docs = load_documents_with_metadata(folder_path)
        
        if not all_docs:
            logger.error(" No documents loaded. Exiting.")
            return
        
        logger.info(f" Total documents loaded: {len(all_docs)}")
        
        # Initialize semantic chunker
        logger.info("\n Initializing Semantic Chunker...")
        semantic_chunker = SemanticChunker(
            similarity_threshold=0.5,
            max_chunk_size=1000
        )
        
        # Chunk documents semantically
        chunks = chunk_documents_semantically(all_docs, semantic_chunker)
        logger.info(f" Total semantic chunks created: {len(chunks)}")
        
        # Create embeddings
        logger.info("\n Loading embedding model...")
        try:
            embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-mpnet-base-v2",
                model_kwargs={"device": "cpu"}
            )
            logger.info(" Embedding model loaded")
        except Exception as e:
            logger.error(f" Failed to load embedding model: {str(e)}")
            return
        
        # Create vector store
        logger.info("\n Creating vector store...")
        try:
            vector_store = FAISS.from_documents(chunks, embeddings)
            retriever = vector_store.as_retriever(search_kwargs={"k": 10})
            logger.info(" Vector store created")
        except Exception as e:
            logger.error(f" Failed to create vector store: {str(e)}")
            return
        
        # Initialize Re-ranker
        logger.info("\n Initializing Cross-Encoder Re-ranker...")
        reranker = CrossEncoderReranker()
        
        # Initialize Output Validator
        logger.info("\n Initializing Output Validator...")
        validator = OutputValidator()
        logger.info(" Output validator initialized")
        
        # Initialize LLM
        logger.info("\n Initializing LLM...")
        try:
            llm = ChatGoogleGenerativeAI(
                model="models/gemma-3-1b-it",
                temperature=0.2
            )
            logger.info(" LLM initialized")
        except Exception as e:
            logger.error(f" Failed to initialize LLM: {str(e)}")
            return
        
        # Create prompt template
        prompt = PromptTemplate(
            template="""You are a helpful cybersecurity assistant that answers questions based on provided context.

IMPORTANT RULES:
- Answer ONLY using information from the context below
- If the context doesn't contain enough information, say "I don't have enough information to answer this question."
- Be specific and cite which document type (XSS, SQLi, or Rules) your answer comes from when possible
- Do not make up information
- Provide clear, technical explanations
- Use examples from the context when available

CONTEXT:
{context}

QUESTION: {question}

ANSWER:""",
            input_variables=["context", "question"]
        )
        
        # Example queries
        questions = [
            "How does XSS attack work?",
            "What is SQL injection and how to prevent it?",
            "Explain CSRF attacks and their mitigation strategies",
            "How does a WAF work?"
        ]
        
        logger.info("\n" + "=" * 70)
        logger.info(" Processing Queries")
        logger.info("=" * 70)
        
        for i, question in enumerate(questions, 1):
            logger.info(f"\n{'='*70}")
            logger.info(f"Query {i}/{len(questions)}")
            logger.info(f"{'='*70}")
            
            result = query_rag(
                question=question,
                retriever=retriever,
                reranker=reranker,
                validator=validator,
                llm=llm,
                prompt_template=prompt,
                initial_k=10,
                final_k=3
            )
            
            if result["success"]:
                print(f"\n QUESTION: {question}")
                print(f"\n ANSWER:\n{result['answer']}")
                print(f"\n SOURCES:")
                for j, source in enumerate(result['sources'], 1):
                    print(f"  {j}. [{source['data_type']}] {source['source']} "
                          f"(Type: {source['file_type']}, Chunk: {source['chunk_id']}, "
                          f"Relevance: {source['relevance_score']})")
                print(f"\n METRICS:")
                print(f"  - Initial retrieval: {result['retrieval_time']} ({result['num_docs_retrieved']} docs)")
                print(f"  - Re-ranking: {result['reranking_time']} ({result['num_docs_reranked']} docs)")
                print(f"  - LLM generation: {result['llm_time']}")
                print(f"  - Validation: {result['validation_time']}")
                print(f"  - Total: {result['total_latency']}")
                print(f"\n VALIDATION:")
                print(f"  - Valid: {result['validation']['is_valid']}")
                print(f"  - Score: {result['validation']['score']:.1f}/100")
                if result['validation']['issues']:
                    print(f"  - Issues: {', '.join(result['validation']['issues'])}")
            else:
                print(f"\n QUESTION: {question}")
                print(f" ERROR: {result['error']}")
            
            print("\n" + "-" * 70)
        
        # Print overall metrics
        logger.info("\n" + "=" * 70)
        logger.info(" OVERALL METRICS")
        logger.info("=" * 70)
        summary = metrics.get_summary()
        for key, value in summary.items():
            logger.info(f"  {key}: {value}")
        
        logger.info("\n" + "=" * 70)
        logger.info(" RAG System Execution Completed Successfully")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}")
        raise

if __name__ == "__main__":
    main()