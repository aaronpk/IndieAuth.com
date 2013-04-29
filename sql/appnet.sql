INSERT INTO `providers` (`name`, `home_page`, `code`, `client_id`, `client_secret`, `regex_username`, `profile_url_template`, `created_at`, `updated_at`)
VALUES
  ('App.net', 'https://alpha.app.net', 'appnet', '', '', 'https?:\\/\\/alpha\\.app\\.net\\/([^\\/]+)', 'https://alpha.app.net/{username}', NOW(), NOW());
