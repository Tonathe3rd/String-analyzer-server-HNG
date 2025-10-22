# Use an official OpenJDK base image
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the source code into the container
COPY ./src /app/src

# Compile the Java file
RUN javac /app/src/StringAnalyzerServer.java

# Expose the default Railway port
EXPOSE 8080

# Set the command to run your Java server
CMD ["java", "-cp", "/app/src", "StringAnalyzerServer"]
