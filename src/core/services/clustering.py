"""
All clustering-related helper functions for payloads
"""


import os
import json
from collections import defaultdict
import hdbscan
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score



def _build_tfidf_vectors(payloads):
    """
    Build character-level TF-IDF vectors
    """
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(5, 10),      # sweet spot for payloads
        min_df=0.2,
        max_df=0.8,
        sublinear_tf=True,
        norm="l2"
    )
    X = vectorizer.fit_transform(payloads)
    return X

def _reduce_dimension(X, n_components=50):
    """
    Reduce sparse TF-IDF vectors for faster clustering
    """
    if X.shape[1] <= n_components:
        return X

    svd = TruncatedSVD(n_components=n_components, random_state=42)
    return svd.fit_transform(X)

DISTANCE_METRICS = {
    "hdbscan": {
        # metric: [các giá trị metric hợp lệ cho param 'metric' của HDBSCAN]
        # Tham khảo: https://hdbscan.readthedocs.io/en/latest/parameter_selection.html#distance-metrics
        "euclidean": {},
        "manhattan": {},
        "l1": {},
        "l2": {},
        "minkowski": {},
        "chebyshev": {},
        "canberra": {},
        "braycurtis": {},
        "mahalanobis": {"requires": ["metric_params: V (covariance matrix)"]},
        "seuclidean": {"requires": ["metric_params: V (variance vector)"]},
        "cosine": {},
        "hamming": {},
        "jaccard": {},
        "matching": {},
        "dice": {},
        "kulsinski": {},
        "rogerstanimoto": {},
        "russellrao": {},
        "sokalmichener": {},
        "sokalsneath": {},
        # ...
        # Ngoài ra có thể truyền callable custom metric
    },
    "hac": {
        # metric: [các giá trị metric hợp lệ cho param 'metric' của AgglomerativeClustering]
        # Lưu ý: linkage ảnh hưởng đến metric hợp lệ
        # linkage="ward" chỉ cho phép metric="euclidean"
        # linkage="average", "complete", "single" cho phép nhiều metric hơn
        "euclidean": {"linkage": ["ward", "average", "complete", "single"]},
        "l1": {"linkage": ["average", "complete", "single"]},
        "l2": {"linkage": ["average", "complete", "single"]},
        "manhattan": {"linkage": ["average", "complete", "single"]},
        "cosine": {"linkage": ["average", "complete", "single"]},
        "precomputed": {"linkage": ["average", "complete", "single"]},
        # ...
        # Nếu dùng linkage="ward" thì chỉ dùng metric="euclidean"
    }
}

def _cluster_payloads_HDBSCAN(X, min_cluster_size=10):
    """
    Perform HDBSCAN clustering
    """
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=int(min_cluster_size),
        min_samples=int(min_cluster_size/2),
        metric="euclidean",   # works because TF-IDF is L2-normalized
        cluster_selection_method="eom"
    )

    labels = clusterer.fit_predict(X)
    return labels

def _cluster_payloads_HAC(X, distance_threshold=1.5):
    """
    Perform Hierarchical Agglomerative Clustering (HAC)
    """
    from sklearn.cluster import AgglomerativeClustering
    # AgglomerativeClustering requires dense input, not sparse
    if hasattr(X, "toarray"):
        X = X.toarray()
    hac = AgglomerativeClustering(
        n_clusters=None, # None for distance_threshold mode
        distance_threshold=distance_threshold, # adjust as needed, or set n_clusters=10 for fixed clusters
        metric="euclidean",
        linkage="ward"
    )
    labels = hac.fit_predict(X)
    return labels
    
def clustering(payloads, reduce_dim_to=100, method="HDBSCAN", cluster_kwargs={}):
    """
    Main clustering function
    """
    data = _build_tfidf_vectors(payloads)
    data_reduced = _reduce_dimension(data, n_components=reduce_dim_to)

    if method == "HDBSCAN":
        return _cluster_payloads_HDBSCAN(data_reduced, **cluster_kwargs)
    elif method == "HAC":
        return _cluster_payloads_HAC(data_reduced, **cluster_kwargs)
    else:
        raise ValueError(f"Unsupported clustering method: {method}")

def evaluate_clusters(X, labels):
    """
    Đánh giá kết quả clustering bằng các metric nội suy phổ biến.
    Trả về dict chứa các giá trị metric.
    """
    results = {}
    # Loại bỏ trường hợp tất cả điểm cùng 1 cluster hoặc noise
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    if n_clusters <= 1:
        results['silhouette_score'] = None
        results['davies_bouldin_score'] = None
        results['calinski_harabasz_score'] = None
        return results

    # Silhouette Score (chỉ tính nếu có >1 cluster và không phải toàn noise)
    try:
        results['silhouette_score'] = silhouette_score(X, labels)
    except Exception:
        results['silhouette_score'] = None

    # Davies-Bouldin Index (càng thấp càng tốt)
    try:
        results['davies_bouldin_score'] = davies_bouldin_score(X, labels)
    except Exception:
        results['davies_bouldin_score'] = None

    # Calinski-Harabasz Index (càng cao càng tốt)
    try:
        results['calinski_harabasz_score'] = calinski_harabasz_score(X, labels)
    except Exception:
        results['calinski_harabasz_score'] = None

    return results

def save_output(data, labels, output_path):
    if not os.path.exists(output_path):
        os.makedirs(output_path, exist_ok=True)
    else:
        for filename in os.listdir(output_path):
            os.remove(os.path.join(output_path, filename))
    
    data_length = len(data)
    clusters = defaultdict(list)
    for raw, label in zip(data, labels):
        clusters[label].append(raw)

    for label, items in sorted(clusters.items(), key=lambda x: (-len(x[1]), x[0])):
        count = len(items)
        ratio = count/data_length
        cluster_label = str(label) if label != -1 else 'NOISE'
        file_name = f"label({cluster_label})_count({count})_ratio({ratio:.2f}).txt"
        file_path = os.path.join(output_path, file_name)
        with open(file_path, "w", encoding="utf-8") as cf:
            for item in items:
                cf.write(item + "\n")

# hàm này chỉ để ví dụ thôi
def example_usage():
    output_folder = "clustering_output"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder, exist_ok=True)

    with open("phase1_balanced_10k.jsonl", "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f]

    payloads = []
    for item in data:
        if item['result'] != 'passed':
            continue
        payloads.append({
            "payload":item["messages"][1]["content"],
            "attack_type":item["attack_type"],
            "technique":item["technique"]
        })

    RAW_PAYLOADS = [item["payload"] for item in payloads] # type: list[str]
    RAW_PAYLOADS = list(set(RAW_PAYLOADS)) # type: list[str]
    print(f"Loaded {len(RAW_PAYLOADS)} unique payloads.")
    
    cluster_labels = clustering(RAW_PAYLOADS, reduce_dim_to=100, method="HAC", cluster_kwargs={"distance_threshold":1.5})
    save_output(RAW_PAYLOADS, cluster_labels, output_path=output_folder)