# Use an official OpenJDK image
FROM openjdk:17-jdk-slim

# Set working directory inside the container
WORKDIR /app

# Copy all files from your repository into the container
COPY . .

# Move into the src folder, compile the main Java file
RUN javac src/StringAnalyzerServer.java

# Expose port 8080 to match default
EXPOSE 8080

# Run the server; instruct Java to find the classpath appropriately
CMD ["java", "-cp", "src", "StringAnalyzerServer"]
