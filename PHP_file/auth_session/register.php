<?php
session_start();
require_once "../config/db.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: ../public/register.html");
    exit;
}

// Get & sanitize inputs
$full_name = trim($_POST['full_name']);
$email     = trim($_POST['email']);
$phone     = trim($_POST['phone']);
$password  = $_POST['password'];
$confirm   = $_POST['confirm_password'];

// Basic validation
if (empty($full_name) || empty($email) || empty($password) || empty($confirm)) {
    $_SESSION['error'] = "All required fields must be filled.";
    header("Location: ../public/register.html");
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error'] = "Invalid email address.";
    header("Location: ../public/register.html");
    exit;
}

if ($password !== $confirm) {
    $_SESSION['error'] = "Passwords do not match.";
    header("Location: ../public/register.html");
    exit;
}

if (strlen($password) < 6) {
    $_SESSION['error'] = "Password must be at least 6 characters.";
    header("Location: ../public/register.html");
    exit;
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $_SESSION['error'] = "Email already registered.";
    header("Location: ../public/register.html");
    exit;
}
$stmt->close();

// Hash password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Insert user
$stmt = $conn->prepare(
    "INSERT INTO users (full_name, email, phone, password) VALUES (?, ?, ?, ?)"
);
$stmt->bind_param("ssss", $full_name, $email, $phone, $hashed_password);

if ($stmt->execute()) {
    $_SESSION['success'] = "Account created successfully. Please login.";
    header("Location: ../public/login.php");
} else {
    $_SESSION['error'] = "Something went wrong. Try again.";
    header("Location: ../public/register.html");
}

$stmt->close();
$conn->close();
