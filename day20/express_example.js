const express = require('express');
const { exec } = require('child_process');

const app = express();
const port = 3000;

app.get('/list-files', (req, res) => {
  const filename = req.query.filename;

  if (!filename) {
    return res.status(400).send('Error: filename query parameter is required.');
  }

  // VULNERABILITY: Command Injection
  // User input from req.query.filename is directly concatenated into a shell command.
  // An attacker can inject arbitrary commands by crafting the filename parameter.
  // For example: ?filename=somefile.txt;ls -la /
  // Or: ?filename=somefile.txt;whoami
  const command = `ls -lh ${filename}`; // Insecurely constructed command

  console.log(`Executing command: ${command}`);

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      // Avoid echoing raw error messages to the client in production
      return res.status(500).send(`Error executing command: ${error.message}`);
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      // Avoid echoing raw stderr to the client in production
      return res.status(500).send(`Command stderr: ${stderr}`);
    }
    res.setHeader('Content-Type', 'text/plain');
    res.send(`Command output for ${filename}:\n${stdout}`);
  });
});

// A safer alternative (if you absolutely must execute commands and only need to list a specific file):
app.get('/list-file-safer', (req, res) => {
  const intendedFile = req.query.file;

  if (!intendedFile) {
    return res.status(400).send('Error: file query parameter is required.');
  }

  // Basic sanitization: allow only alphanumeric, dots, and underscores.
  // This is still not foolproof and depends heavily on context.
  // Whitelisting known good values is always better.
  const sanitizedFile = intendedFile.replace(/[^a-zA-Z0-9._-]/g, '');

  if (sanitizedFile !== intendedFile || sanitizedFile.includes('..')) {
      return res.status(400).send('Error: Invalid characters in filename or path traversal attempt.');
  }

  // Using execFile is generally safer as it doesn't invoke a shell by default.
  // The command and its arguments are passed as separate array elements.
  execFile('ls', ['-lh', sanitizedFile], (error, stdout, stderr) => {
    if (error) {
      console.error(`execFile error: ${error}`);
      return res.status(500).send(`Error executing command: ${error.message}`);
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return res.status(500).send(`Command stderr: ${stderr}`);
    }
    res.setHeader('Content-Type', 'text/plain');
    res.send(`Command output for ${sanitizedFile} (using execFile):\n${stdout}`);
  });
});


app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
  console.log('Try: http://localhost:3000/list-files?filename=express_example.js');
  console.log('Vulnerable: http://localhost:3000/list-files?filename=express_example.js;whoami');
  console.log('Safer attempt: http://localhost:3000/list-file-safer?file=express_example.js');
});
