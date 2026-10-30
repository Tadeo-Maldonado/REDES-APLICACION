@echo off
REM Inicia NetOrch en Windows. La primera vez crea el entorno e instala dependencias.
cd /d "%~dp0"
if not exist .venv (
    python -m venv .venv
    call .venv\Scripts\activate
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate
)
streamlit run app.py
