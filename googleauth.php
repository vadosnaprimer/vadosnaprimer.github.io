<?php
function str_ends($haystack, $needle)
{
  $len_haystack = strlen($haystack);
  $len_needle = strlen($needle);
  return(($len_haystack >= $len_needle) && (substr_compare($haystack, $needle, $len_haystack - $len_needle, $len_needle) === 0));
}

function url_self()
{
  $secure = !empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] !== 'off');
  $port = (int)$_SERVER['SERVER_PORT'];
  $host = strtolower($_SERVER['HTTP_HOST']);
  $port_default = $secure ? 443 : 80;
  $port_str = ':'.$port;
  if (($port !== $port_default) && !str_ends($host, $port_str)) { $host .= $port_str; }
  return('http'.($secure ? 's' : '').'://'.$host.$_SERVER['PHP_SELF']);
}

if (isset($_GET['state'], $_GET['code']))
{
  $j = json_decode(base64_decode($_GET['state'], true));
  if (is_object($j) && isset($j->url, $j->id, $j->secret))
  {
    $post = array
    (
      'code' => $_GET['code'],
      'client_id' => $j->id,
      'client_secret' => $j->secret,
      'grant_type' => 'authorization_code',
      'redirect_uri' => url_self() //This parameter is utterly useless at this point, but of course Google wants it anyway
    );

    $curl = curl_init($j->url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
    $headers = array();
    curl_setopt($curl, CURLOPT_HEADERFUNCTION, function($curl, $header)
    {
      global $headers;
      $pos = strpos($header, ': ');
      if ($pos) { $headers[substr($header, 0, $pos)] = trim(substr($header, $pos+2)); }
      return(strlen($header));
    });

    $response = curl_exec($curl);
    if ($response !== false)
    {
      $http_code = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
      if ($http_code === 200)
      {
        $j2 = json_decode($response);
        if (is_object($j2) && isset($j2->refresh_token))
        {
          $credentials = array
          (
            'token_uri' => $j->url,
            'client_id' => $j->id,
            'client_secret' => $j->secret,
            'refresh_token' => $j2->refresh_token,
            'grant_type' => 'refresh_token'
          );
          $json = json_encode($credentials, JSON_UNESCAPED_SLASHES);

          header('Content-Type: application/json');
          header('Content-Length: '.strlen($json));
          header('Content-MD5: '.base64_encode(md5($json, true)));
          header('Content-Disposition: attachment; filename=credentials.json');
          echo $json;
          exit;
        }
        else
        {
          http_response_code(502);
          header('Content-Type: text/plain');
          echo 'Request did not contain "refresh_token", received:', "\n";
          print_r($j2);
        }
      }
      else
      {
        http_response_code(502);
        header('Content-Type: text/plain');
        echo $http_code, "\n";
        print_r($headers);
        echo $response;
      }
    }
    else
    {
      http_response_code(502);
      header('Content-Type: text/plain');
      echo curl_error($curl);
    }
  }
  else
  {
    http_response_code(502);
    header('Content-Type: text/plain');
    echo 'Google did not respond with a valid "state" parameter';
  }
}
else 
if (isset($_GET['scope']))
{
  if (isset($_FILES['json']))
  {
    $json = file_get_contents($_FILES['json']['tmp_name']);
    $j = json_decode($json);
    if (is_object($j) && isset($j->web, $j->web->auth_uri, $j->web->client_secret, $j->web->token_uri, $j->web->redirect_uris, $j->web->client_id))
    {
      $self = url_self();
      if (in_array($self, $j->web->redirect_uris))
      {
        $state = array('url' => $j->web->token_uri, 'id' => $j->web->client_id, 'secret' => $j->web->client_secret);
        $url = $j->web->auth_uri.'?client_id='.rawurlencode($j->web->client_id).
                                 '&redirect_uri='.rawurlencode($self).
                                 '&scope='.rawurlencode($_GET['scope']).
                                 '&response_type=code'.
                                 '&access_type=offline'.
                                 '&state='.rawurlencode(base64_encode(json_encode($state)));
        http_response_code(303);
        header('Location: '.$url);
      }
      else
      {
        http_response_code(400);
        header('Content-Type: text/plain');
        echo 'Uploaded Authentication JSON is not setup for this URL';
      }
    }
    else
    {
      http_response_code(400);
      header('Content-Type: text/plain');
      echo 'Uploaded Authentication JSON is invalid';
    }
  }
  else
  {
    echo '<!DOCTYPE html>
<html>
  <head>
    <title>Retrieve Google API Credentials</title>
     <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  </head>
  <body>
  <form action="', htmlspecialchars($_SERVER['PHP_SELF']),'?scope=', htmlspecialchars(rawurlencode($_GET['scope'])),'" method="post" enctype="multipart/form-data">
    Select Google Authentication JSON to upload:<br />
    <input type="file" name="json" accept="application/json"><br />
    <input type="submit" value="Upload JSON"><br />
  </form>
  </body>
</html>';
  }
}
else
{
  echo '<!DOCTYPE html>
<html>
  <head>
    <title>Retrieve Google API Credentials</title>
     <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  </head>
  <body>
  <form action="', htmlspecialchars($_SERVER['PHP_SELF']),'" method="get">
    Scope for Google Authentication:<br />
    <input type="text" name="scope"><br />
    <input type="submit" value="Proceed"><br />
  </form>
  </body>
</html>';
}

