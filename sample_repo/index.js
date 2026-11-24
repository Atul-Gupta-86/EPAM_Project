// Sample vulnerable code for testing security scanning tools
const aws_key = "AKIAIOSFODNN7EXAMPLE"; // Gitleaks test secret
const secret_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";

function runQuery(userInput) {
  // eval / unsafe execution
  eval(userInput);
}
