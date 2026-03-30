import os
import shutil
import google.generativeai as genai
import chromadb
from chromadb.utils import embedding_functions

# 1. Define a Custom Embedding Function for Chroma
class GeminiEmbeddingFunction(chromadb.EmbeddingFunction):
    def __call__(self, input: list[str]) -> list[list[float]]:
        # models/text-embedding-004 is the standard
        result = genai.embed_content(
            model="models/text-embedding-004",
            content=input,
            task_type="retrieval_document"
        )
        return result['embedding']

# 2. The RAG Manager
class RAGChatbot:
    def __init__(self, db_path="./output/chroma_db"):
        self.db_path = db_path
        self.chroma_client = chromadb.PersistentClient(path=db_path)
        self.embed_fn = GeminiEmbeddingFunction()
        
        self.collection = self.chroma_client.get_or_create_collection(
            name="astra_findings",
            embedding_function=self.embed_fn
        )

    def ingest_findings(self, findings):
        """Reset collection and add new findings."""
        self.chroma_client.delete_collection("astra_findings")
        self.collection = self.chroma_client.create_collection(
            name="astra_findings",
            embedding_function=self.embed_fn
        )
        
        ids = []
        documents = []
        metadatas = []
        
        for idx, f in enumerate(findings):
            # Create a rich text representation for the vector store
            text_rep = (f"Target: {f.target} detected by {f.source_tool}. "
                        f"Type: {f.finding_type}. Value: {f.finding_value}. "
                        f"Details: {f.details}")
            
            ids.append(f"find_{idx}")
            documents.append(text_rep)
            metadatas.append({"tool": f.source_tool, "type": f.finding_type})
            
        if documents:
            self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
            print(f"[AI] Ingested {len(documents)} findings into RAG.")

    def query(self, user_question):
        """Retrieve context and answer question."""
        # 1. Search Vector DB
        results = self.collection.query(
            query_texts=[user_question],
            n_results=5
        )
        
        context_list = results['documents'][0]
        context_str = "\n\n".join(context_list)
        
        # 2. Send to Gemini
        from .client import get_model
        model = get_model()
        
        prompt = f"""
        You are ASTRA, a security assistant. 
        Answer the user's question using ONLY the provided context.
        
        Context (Scan Results):
        {context_str}
        
        User Question: {user_question}
        
        Answer:
        """
        
        response = model.generate_content(prompt)
        return response.text