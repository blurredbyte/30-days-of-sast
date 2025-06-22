// example.js
function executeUserInput(input) {
  eval(input); // Potentially dangerous if input is not sanitized
}

// Example of legitimate use (though still risky)
executeUserInput("console.log('Hello from eval!')");

// Example of how it could be exploited if input is from an external source
// const userInput = "require('child_process').exec('touch /tmp/exploited')";
// executeUserInput(userInput);
