<?php
include 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Sanitization Methods:
    // htmlspecialchars()
    // trim() 
    // filter_var() 

    $fname = trim(filter_var(htmlspecialchars($_POST['first_name'], ENT_QUOTES, 'UTF-8'), FILTER_SANITIZE_STRING));
    $lname = trim(filter_var(htmlspecialchars($_POST['last_name'], ENT_QUOTES, 'UTF-8'), FILTER_SANITIZE_STRING));
    $uname = trim(filter_var(htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8'), FILTER_SANITIZE_STRING));
    $pass = trim($_POST['password']); 

    // Encrypt password using bcrypt for security
    $encryptpass = password_hash($pass, PASSWORD_BCRYPT);

    // Prepared statement to prevent SQL Injection
    $sql = "INSERT INTO users (first_name, last_name, username, password) VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ssss", $fname, $lname, $uname, $encryptpass);

    if ($stmt->execute()) {
        header("Location: login.php");
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>

<form method="POST" action="register.php">
    <input type="text" name="first_name" placeholder="First Name" required><br>
    <input type="text" name="last_name" placeholder="Last Name" required><br>
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Register</button>
</form>
