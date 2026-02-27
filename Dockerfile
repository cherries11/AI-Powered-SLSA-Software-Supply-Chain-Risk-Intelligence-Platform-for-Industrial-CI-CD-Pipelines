# 1️⃣ Base image
FROM python:3.11-slim

# 2️⃣ Set working directory inside container
WORKDIR /app

# 3️⃣ Copy backend + frontend + requirements
COPY backend/ backend/
COPY frontend/ frontend/
COPY backend/requirements.txt .

# 4️⃣ Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 5️⃣ Expose port for Streamlit
EXPOSE 8501

# 6️⃣ Default command: run Streamlit MVP
CMD ["streamlit", "run", "frontend/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]