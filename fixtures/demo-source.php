<?php
// Harmless static-analysis fixture. This sample is never executed by the application.
$input = $_POST['text'] ?? '';
$decoded = base64_decode($input);
echo htmlspecialchars($decoded, ENT_QUOTES, 'UTF-8');
