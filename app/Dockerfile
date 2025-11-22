FROM python:3.11

RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

# Переменнаые для Selenium
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER=/usr/bin/chromedriver

COPY . /app
WORKDIR /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
