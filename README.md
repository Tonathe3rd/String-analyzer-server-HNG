## String Analyzer REST API

A lightweight Java RESTful API that analyzes strings and computes various properties — such as their length, word count, uniqueness, and whether they’re palindromes — while storing each result for retrieval.

Built as part of the HNG Internship (Stage 2).

## 🚀 Features

✅ Analyze any string and compute detailed properties
✅ Retrieve a specific analyzed string or view all stored ones
✅ Filter results using query parameters
✅ Natural language filtering (e.g., “all single word palindromic strings”)
✅ Delete previously analyzed strings

🧩 API Endpoints Overview
Method	Endpoint	Description
POST	/strings	Analyze a new string
GET	/strings/{string_value}	Get details of a specific string
GET	/strings	Retrieve all analyzed strings (with filters)
GET	/strings/filter-by-natural-language	Filter using natural language queries
DELETE	/strings/{string_value}	Delete a specific string
🛠️ Setup Instructions
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/String-analyzer-server-HNG.git
cd String-analyzer-server-HNG

2️⃣ Install Dependencies

Ensure you have Java 17 or later installed:

java -version


If not, download and install from 👉 https://adoptium.net

3️⃣ Compile the Server

From the root directory:

javac src/StringAnalyzerServer.java

4️⃣ Run Locally
java -cp src StringAnalyzerServer


Once started, your API will be live at:
👉 http://localhost:8080

Try testing this endpoint in your browser:

http://localhost:8080/strings

🧮 Example Usage
➕ POST /strings

Request Body:

{
  "value": "level"
}


Response (201 Created):

{
  "id": "cde2344...",
  "value": "level",
  "properties": {
    "length": 5,
    "is_palindrome": true,
    "unique_characters": 3,
    "word_count": 1,
    "sha256_hash": "cde2344...",
    "character_frequency_map": {
      "l": 2,
      "e": 2,
      "v": 1
    }
  },
  "created_at": "2025-10-22T12:00:00Z"
}

⚙️ Environment Variables

No environment variables are required — everything runs by default on port 8080.

🐳 Docker Setup (Optional)

If deploying with Docker (e.g., via Railway):

Ensure Docker is installed

Build the image:

docker build -t string-analyzer .


Run the container:

docker run -p 8080:8080 string-analyzer


The app will be available at:
👉 http://localhost:8080

📦 Dependencies
Dependency	Purpose
java.net	HTTP Server & network communication
java.security	SHA-256 hashing
java.time	Timestamp generation
java.util	String and collection utilities

🧪 Testing the API

Use curl or Postman:

curl -X POST http://localhost:8080/strings \
  -H "Content-Type: application/json" \
  -d '{"value": "hello world"}'


👨‍💻 Author

Adeshola Adetona
📧 Email: get2adeshola@gmail.com

💻 Stack: Java
🌍 HNG Internship — Stage 2
