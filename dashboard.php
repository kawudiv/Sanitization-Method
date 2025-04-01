<?php
session_start();
include 'config.php';

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

// Sanitization Methods:
// htmlspecialchars() 
// trim() 
// filter_var() 

$username = trim(filter_var(htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'), FILTER_SANITIZE_STRING));

$sql = "SELECT username FROM users WHERE username = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 1) {
    $row = $result->fetch_assoc();
    $username = $row["username"];
} else {
    $username = "Unknown User";
}

$stmt->close();
$conn->close();
?>

<h2>Welcome, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>!</h2>
<p>You have successfully logged in.</p>
<a href="logout.php">Logout</a>
