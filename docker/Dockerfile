# Usar una imagen base de Python
FROM python:3.8-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar los archivos requeridos al contenedor
COPY . /app

# Instalar Flask
RUN pip install flask flask-cors requests

# Exponer el puerto en el que se ejecutará la aplicación
EXPOSE 8080

# Comando para iniciar la aplicación
CMD ["python", "./main.py"]
