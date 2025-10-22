# Use official JDK image
FROM openjdk:17-jdk-slim

# Set working directory
WORKDIR /app

# Copy all project files into the container
COPY . .

# Compile your Java file (replace with your actual main file name)
RUN javac StringAnalyzerServer.java

# Expose port 8080 for Railway
EXPOSE 8080

# Run your server
CMD ["java", "StringAnalyzerServer"]
