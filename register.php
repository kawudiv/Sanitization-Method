<?php
include 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // ✅ Input Sanitization: htmlspecialchars() - Prevents XSS by encoding special characters
    // ✅ Input Sanitization: trim() - Removes unnecessary spaces before/after the input
    $fname = trim(htmlspecialchars($_POST['first_name'], ENT_QUOTES, 'UTF-8'));
    $lname = trim(htmlspecialchars($_POST['last_name'], ENT_QUOTES, 'UTF-8'));
    $uname = trim(htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8'));
    $pass = trim($_POST['password']); // Password should not be sanitized with htmlspecialchars()

    // ✅ Password Hashing - Encrypts password using bcrypt for security
    $encryptpass = password_hash($pass, PASSWORD_BCRYPT);

    // ✅ SQL Injection Prevention: Prepared Statements using bind_param()
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
