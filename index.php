<?php
require_once "vendor/autoload.php";

use \Dropbox as dbx;

$appInfoFile = 'app-info.json';
$route = isset($_GET["route"]) ? $_GET['route'] : '';

session_start();

if (empty($route)) {
    $dbxClient = getClient();

    if ($dbxClient === false) {
        header("Location: ".getPath("dropbox-auth-start"));
        exit;
    }

    $path = "/";
    if (isset($_GET['path'])) $path = $_GET['path'];

    $entry = $dbxClient->getMetadataWithChildren($path);
    if ($entry['is_dir']) {
        echo renderFolder($entry);
    }
    else {
        echo renderFile($entry);
    }
}
else if ($route == "download") {
    $dbxClient = getClient();

    if ($dbxClient === false) {
        header("Location: ".getPath("dropbox-auth-start"));
        exit;
    }

    if (!isset($_GET['path'])) {
        header("Location: ".getPath(""));
        exit;
    }
    $path = $_GET['path'];

    $fd = tmpfile();
    $metadata = $dbxClient->getFile($path, $fd);

    header("Content-Type: $metadata[mime_type]");
    fseek($fd, 0);
    fpassthru($fd);
    fclose($fd);
}
else if ($route === "upload") {
    if (empty($_FILES['file']['name'])) {
        echo renderHtmlPage("Error", "Please choose a file to upload");
        exit;
    }

    if (!empty($_FILES['file']['error'])) {
        echo renderHtmlPage("Error", "Error ".$_FILES['file']['error']." uploading file.  See <a href='http://php.net/manual/en/features.file-upload.errors.php'>the docs</a> for details");
        exit;
    }

    $dbxClient = getClient();

    $remoteDir = "/";
    if (isset($_POST['folder'])) $remoteDir = $_POST['folder'];

    $remotePath = rtrim($remoteDir, "/")."/".$_FILES['file']['name'];

    $fp = fopen($_FILES['file']['tmp_name'], "rb");
    $result = $dbxClient->uploadFile($remotePath, dbx\WriteMode::add(), $fp);
    fclose($fp);
    $str = print_r($result, TRUE);
    echo renderHtmlPage("Uploading File", "Result: <pre>$str</pre>");
}
else if ($route === "dropbox-auth-start") {
    $authorizeUrl = getWebAuth()->start();
    header("Location: $authorizeUrl");
}
else if ($route === "dropbox-auth-finish") {
    try {
        list($accessToken, $userId, $urlState) = getWebAuth()->finish($_GET);
        // We didn't pass in $urlState to finish, and we're assuming the session can't be
        // tampered with, so this should be null.
        assert($urlState === null);
    }
    catch (dbx\WebAuthException_BadRequest $ex) {
        respondWithError(400, "Bad Request");
        // Write full details to server error log.
        // IMPORTANT: Never show the $ex->getMessage() string to the user -- it could contain
        // sensitive information.
        error_log("/dropbox-auth-finish: bad request: " . $ex->getMessage());
        exit;
    }
    catch (dbx\WebAuthException_BadState $ex) {
        // Auth session expired.  Restart the auth process.
        header("Location: ".getPath("dropbox-auth-start"));
        exit;
    }
    catch (dbx\WebAuthException_Csrf $ex) {
        respondWithError(403, "Unauthorized", "CSRF mismatch");
        // Write full details to server error log.
        // IMPORTANT: Never show the $ex->getMessage() string to the user -- it contains
        // sensitive information that could be used to bypass the CSRF check.
        error_log("/dropbox-auth-finish: CSRF mismatch: " . $ex->getMessage());
        exit;
    }
    catch (dbx\WebAuthException_NotApproved $ex) {
        echo renderHtmlPage("Not Authorized?", "Why not?");
        exit;
    }
    catch (dbx\WebAuthException_Provider $ex) {
        error_log("/dropbox-auth-finish: unknown error: " . $ex->getMessage());
        respondWithError(500, "Internal Server Error");
        exit;
    }
    catch (dbx\Exception $ex) {
        error_log("/dropbox-auth-finish: error communicating with Dropbox API: " . $ex->getMessage());
        respondWithError(500, "Internal Server Error");
        exit;
    }

    // NOTE: A real web app would store the access token in a database.
    $_SESSION['access-token'] = $accessToken;

    echo renderHtmlPage("Authorized!",
        "Auth complete, <a href='".htmlspecialchars(getPath(""))."'>click here</a> to browse.");
}
else if ($route === "dropbox-auth-unlink") {
    // "Forget" the access token.
    unset($_SESSION['access-token']);
    echo renderHtmlPage("Unlinked.",
        "Go back <a href='".htmlspecialchars(getPath(""))."'>home</a>.");
}
else {
    echo renderHtmlPage("Bad URL", "No handler for $requestPath");
    exit;
}

function renderFolder($entry)
{
    // TODO: Add a token to counter CSRF attacks.
    $upload_path = htmlspecialchars(getPath('upload'));
    $path = htmlspecialchars($entry['path']);
    $form = <<<HTML
        <form action='$upload_path' method='post' enctype='multipart/form-data'>
        <label for='file'>Upload file:</label> <input name='file' type='file'/>
        <input type='submit' value='Upload'/>
        <input name='folder' type='hidden' value='$path'/>
        </form>
HTML;

    $listing = '';
    foreach($entry['contents'] as $child) {
        $cp = $child['path'];
        $cn = basename($cp);
        if ($child['is_dir']) $cn .= '/';

        $cp = htmlspecialchars($cp);
        $link = getPath("&path=".htmlspecialchars($cp));
        $listing .= "<div><a style='text-decoration: none' href='$link'>$cn</a></div>";
    }

    return renderHtmlPage("Folder: $entry[path]", $form.$listing);
}

function getAppConfig()
{
    global $appInfoFile;

    try {
        $appInfo = dbx\AppInfo::loadFromJsonFile($appInfoFile);
    }
    catch (dbx\AppInfoLoadException $ex) {
        throw new Exception("Unable to load \"$appInfoFile\": " . $ex->getMessage());
    }

    $clientIdentifier = "examples-web-file-browser";
    $userLocale = null;

    return array($appInfo, $clientIdentifier, $userLocale);
}

function getClient()
{
    if(!isset($_SESSION['access-token'])) {
        return false;
    }

    list($appInfo, $clientIdentifier, $userLocale) = getAppConfig();
    $accessToken = $_SESSION['access-token'];
    return new dbx\Client($accessToken, $clientIdentifier, $userLocale, $appInfo->getHost());
}

function getWebAuth()
{
    list($appInfo, $clientIdentifier, $userLocale) = getAppConfig();
    $redirectUri = getPath("dropbox-auth-finish");
    $csrfTokenStore = new dbx\ArrayEntryStore($_SESSION, 'dropbox-auth-csrf-token');
    return new dbx\WebAuth($appInfo, $clientIdentifier, $redirectUri, $csrfTokenStore, $userLocale);
}

function renderFile($entry)
{
    $metadataStr = htmlspecialchars(print_r($entry, true));
    $downloadPath = getPath("download&path=".htmlspecialchars($entry['path']));
    $body = <<<HTML
        <pre>$metadataStr</pre>
        <a href="$downloadPath">Download this file</a>
HTML;

    return renderHtmlPage("File: ".$entry['path'], $body);
}

function renderHtmlPage($title, $body)
{
    return <<<HTML
    <html>
        <head>
            <title>$title</title>
        </head>
        <body>
            <h1>$title</h1>
            $body
        </body>
    </html>
HTML;
}

function respondWithError($code, $title, $body = "")
{
    $proto = $_SERVER['SERVER_PROTOCOL'];
    header("$proto $code $title", true, $code);
    echo renderHtmlPage($title, $body);
}



function getPath($relative_path)
{
    return "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']  . '?route=' . $relative_path;
}

