<?php
include 'config.php';
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitization Methods:
    // htmlspecialchars()
    // trim() 
    // filter_var() 
    
    $uname = trim(filter_var(htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8'), FILTER_SANITIZE_STRING));
    $pass = trim($_POST['password']);

    // Prepared Statements using bind_param()
    $sql = "SELECT id, password FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $uname);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        $hashed_pass = $row["password"];

        if (password_verify($pass, $hashed_pass)) {
            $_SESSION['username'] = $uname;
            header("Location: dashboard.php");
        } else {
            echo "Invalid password!";
        }
    } else {
        echo "User not found!";
    }

    $stmt->close();
    $conn->close();
}
?>

<form method="POST" action="login.php">
    <input type="text" name="username" placeholder="Username" required><br>
    <input type="password" name="password" placeholder="Password" required><br>
    <button type="submit">Login</button>
</form>

<form action="register.php" method="GET">
    <button type="submit">Sign Up</button>
</form>
