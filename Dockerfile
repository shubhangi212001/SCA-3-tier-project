# Use Python 3.7 as the base image
FROM python:3.7

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /sca

# Install dependencies
COPY requirements.txt /sca/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy the FastAPI application into the container
COPY . /sca/

# Expose the port number that the FastAPI application runs on
EXPOSE 8070

# Command to run the FastAPI application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8070"]
