<?php

/* Define some states for the netstring parser. */
define('INITIAL', 0);
define('IN_HEADER', 1);
define('DATA', 2);
define('ENDOFDATA', 3);
define('SUCCESS', 4);
define('ERROR', 5);

class NetstringPlusState {
    private $state = INITIAL;
    private $length = 0;
    private $position = 0;
    private $data;
    private $error;

    public function state() { return $this->state; }
    public function error() { return $this->error; }

    public function __construct() {
        $this->Reset();
    }

    public function Reset() {
        $this->state = INITIAL;
        $this->length = 0;
        $this->position = 0;
        $this->data = null;
        $this->error = null;
    }

    /* Return the optimum size for the next read. */
    public function NextReadSize() {
        switch($this->state) {
        case INITIAL:
        case IN_HEADER:
        case ENDOFDATA:
            return 1;
        case DATA:
            return $this->length - $this->position;
        case SUCCESS:
            return 0;
        default:
            throw new Exception("Invalid decoder state $this->state");
        }
    }

    /* Run a byte through the parser, updating the internal state as necessary. */
    public function PumpByte($b)
    {
        switch($this->state) {
        case INITIAL:
        case IN_HEADER:
            $n = $this->AsciiHexDigit(ord($b));
            if ($b == ':') {
                if ($this->state == INITIAL) {
                    throw new Exception("Netstring header is empty");
                }
                $this->position = 0;
                $this->data = str_repeat(' ', $this->length);
                if ($this->length == 0)
                    $this->TransitionState(ENDOFDATA);
                else
                    $this->TransitionState(DATA);
            } else if ($n < 0) {
                throw new Exception("Invalid header character: '$b'");
            } else {
                $this->AddHeaderDigit($n);
                if ($this->state == INITIAL)
                    $this->TransitionState(IN_HEADER);
            }

            break;
        case DATA:
            $this->data[$this->position++] = $b;
            if ($this->position == $this->length)
                $this->TransitionState(ENDOFDATA);
            break;
        case ENDOFDATA:
            if ($b != "\n")
                throw new Exception("Too much data in netstring, character is'$b'");
            $this->TransitionState(SUCCESS);
            break;
        case SUCCESS:
            throw new Exception("Decoder is already complete");
        default:
            throw new Exception("Invalid decode state: $this->state");
        }
    }

    /* Run a byte array through the decoder, returning an array of all messages parsed.
     * $start and $end limit parsing to a subsection of the array, and $count limits
     * the number of messages that will be parsed.
     */
    public function PumpArray($arr, $start = 0, $end = null, $count = null)
    {
        $numMessages = 0;
        $messages = Array();
        if ($end == null)
            $end = strlen($arr);

        while ($start < $end && ($count == null || i < count)) {
            $b = $arr[$start];
            /* Get a fresh state if this one is already complete. */
            if ($this->state == SUCCESS) { $this->Reset(); }

            $this->PumpByte($b);
            $start++;

            if ($this->state == SUCCESS) {
                $messages[] = $this->data;
                $numMessages++;
            }
        }
        return $messages;
    }

    /* Run a stream through the decoder, returning an array of all messages parsed.
     * $bytes limits the number of bytes read from the stream, $count limits the
     * number of messages parsed.
     */
    public function PumpStream($stream, $bytes = null, $count = null)
    {
        $message = Array();
        $numMessages = 0;
        $byteCount = 0;


        while (!feof($stream) && ($bytes == null || $byteCount < $bytes) && ($count == null || $numMessages < $count))
        {
            /* If the decoder is already complete, get a fresh state. */
            if ($this->state == SUCCESS)
                $this->Reset();

            $data = fread($stream, $this->NextReadSize());
            if ($data !== FALSE) {
                $byteCount += strlen($data);
                $msgs = $this->PumpArray($data);
                if ($this->state == SUCCESS) {
                    /* We'll only ever get one message out of this. */
                    $message[] = $msgs[0];
                    $numMessages++;
                }
            }
        }
        return $message;
    }

    private function BadTransition($oldstate, $newstate)
    {
        throw new Exception("Invalid state transition from $oldstate to $newstate");
    }

    private function TransitionState($newstate)
    {
        switch($this->state) {
        case INITIAL:
            if ($newstate != IN_HEADER)
                $this->BadTransition($this->state, $newstate);
            break;
        case IN_HEADER:
            if ($newstate != DATA && $newstate != ENDOFDATA)
                $this->BadTransition($this->state, $newstate);
            break;
        case DATA:
            if ($newstate != ENDOFDATA)
                $this->BadTransition($this->state, $newstate);
            break;
        case ENDOFDATA:
            if ($newstate != SUCCESS)
                $this->BadTransition($this->state, $newstate);
            break;
        default:
            throw new Exception("Invalid decoder state $this->state");
        }

        $this->state = $newstate;
    }

    private function AddHeaderDigit($i)
    {
        /* Base 16 digits, so shift (multiply by the base) and add. */
        $this->length = $this->length * 16 + $i;
    }

    public function AsciiHexDigit($b)
    {
        if ($b <= ord('9') && $b >= ord('0'))
            return $b - ord('0');
        else if ($b >= ord('a') && $b <= ord('f'))
            return $b - ord('a') + 10;
        else if ($b >= ord('A') && $b <= ord('F'))
            return $b - ord('A') + 10;
        else
            return -1;
    }
}

class NetstringPlusAPI {
    private static function NetstringHeader($data)
    {
        $len = strlen($data);
        return strtoupper(dechex($len) . ':');
    }

    /* Write a modified netstring to $stream with a payload of $data. */
    public static function WriteNetstringBytes($stream, $data)
    {
        // FIXME: For large payloads, concatenation performs
        // poorly. However, PHP appears not to allow write buffering
        // on sockets, so for smaller payloads concatenation in-memory
        // is better than sending three separate packets.
        $outData = NetstringPlusAPI::NetstringHeader($data) . $data . "\n";
        fwrite($stream, $outData);
        fflush($stream);
    }

    /* Read one netstring from $stream and return its payload, or FALSE
     * if a full message couldn't be parsed.
     */
    public static function ReadNetstringData($stream)
    {
        $state = new NetstringPlusState();
        /* Parse at most one message from the stream. */
        $messages = $state->PumpStream($stream, null, 1);
        if (count($messages) < 1)
            return FALSE;
        return $messages[0];
    }
}

class TcpTransport {
    private $host;
    private $port;
    private $sock;
    private $stream;
    private $use_keepalive;
    private $keepalive_timeout;

    public function __construct($host, $port, $use_keepalive = TRUE, $keepalive_timeout = null)
    {
        $this->host = $host;
        $this->port = $port;
        $this->use_keepalive = $use_keepalive;
        $this->keepalive_timeout = $keepalive_timeout;
    }

    public function Connect()
    {
        /* Make sure we're disconnected first. */
        $this->Disconnect();

        $this->stream = fsockopen($this->host, $this->port, $errno, $errstring);
        if (!$this->stream)
            throw new Exception("($errno) Error connecting to host tcp://$this->host:$this->port: $errstring");

        /* We really probably don't want to send a separate packet for every fwrite().
         * We're calling fflush() in the right places, so a large buffer doesn't hurt here.
         */
        stream_set_write_buffer($this->stream, 4096);

        $this->sock = socket_import_stream($this->stream);

        /* There's almost never a good reason to avoid TCP keepalive here. */
        if ($this->use_keepalive) {
            socket_set_option($this->sock, SOL_SOCKET, SO_KEEPALIVE, 1);
            if ($this->keepalive_timeout != null)
                // FIXME: there is no named constant for TCP_KEEPIDLE, but we need to use it.
                // Fix this to be portable (ish).
                socket_set_option($this->sock, SOL_SOCKET, 4, $this->keepalive_timeout);
        }
    }

    public function Disconnect()
    {
        if ($this->stream != null) {
            fclose($this->stream);
            $this->stream = null;
            $this->sock = null;
        }
    }

    public function SendMessage($data)
    {
        NetstringPlusAPI::WriteNetstringBytes($this->stream, $data);
    }

    public function ReadMessage()
    {
        return NetstringPlusApi::ReadNetstringData($this->stream);
    }
}

class MTGNetConnection
{
    protected $transport;

    public static function CallObj($id, $service, $method, $args)
    {
        return Array(
            'Id' => $id,
            'Service' => $service,
            'Method' => $method,
            'Args' => $args
        );
    }

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function Connect()
    {
        $this->transport->Connect();
    }

    public function Disconnect()
    {
        $this->transport->Disconnect();
    }

    public function SubmitCallBatch($batch)
    {
        $requestData = json_encode($batch);
        $this->transport->SendMessage($requestData);

        $response = json_decode($this->transport->ReadMessage());
        return $response;
    }

    public function InvokeRPCMethod($callId, $service, $method, $args)
    {
        $callobj = Array(
            'Service' => $service,
            'Method' => $method,
            'Id' => $callId,
            'Args' => $args
        );
        return $this->SubmitCallBatch(Array($callobj));
    }
}

class EncryptedMTGNetConnection extends MTGNetConnection
{
    private $secret;
    private $serverKeys;
    private $sessionKeypair;

    public static function GenerateEncodedSecret()
    {
        $pair = \Sodium\crypto_sign_keypair();
        $secret = \Sodium\crypto_sign_secretkey($pair);
        return base64_encode($secret);
    }

    public static function DecodeSecret($secret64)
    {
        return base64_decode($secret64);
    }

    public function __construct($transport, $secret, $serverKeys = null)
    {
        $this->serverKeys = $serverKeys;
        $this->secret = $secret;
        parent::__construct($transport);
    }

    public function PerformHandshake()
    {
        $signingPublic = \Sodium\crypto_sign_publickey_from_secretkey($this->secret);

        $ephemeralKeypair = \Sodium\crypto_box_keypair();

        $ephemeralPublic = \Sodium\crypto_box_publickey($ephemeralKeypair);
        $signedPublic = \Sodium\crypto_sign($ephemeralPublic, $this->secret);

        /* Send the signing key and the ephemeral public key to the remote party. */
        $this->transport->SendMessage($signingPublic . $signedPublic);

        /* Read the corresponding message. */
        $remoteMsg = $this->transport->ReadMessage();
        if (strlen($remoteMsg) != \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES + \Sodium\CRYPTO_BOX_PUBLICKEYBYTES + \Sodium\CRYPTO_SIGN_BYTES)
            throw new Exception("Received invalid handshake message of length " . strlen($remoteMsg));

        $remoteSigningPublic = substr($remoteMsg, 0, \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES);
        $remoteSignedPublic = substr($remoteMsg, \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES);

        if ($this->serverKeys != null && !in_array($remoteSigningPublic, $this->serverKeys))
            throw new Exception("Unrecognized key received from remote party: " . base64_encode($remoteSigningPublic));

        $remoteEphemeralPublic = \Sodium\crypto_sign_open($remoteSignedPublic, $remoteSigningPublic);
        if (!$remoteEphemeralPublic)
            throw new Exception("Signature on session key is invalid; the remote party is an impostor!");

        $sessionSecret = \Sodium\crypto_box_secretkey($ephemeralKeypair);
        $this->sessionKeypair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey($sessionSecret, $remoteEphemeralPublic);
    }

    public function Connect() {
        parent::Connect();
        $this->PerformHandshake();
    }

    public function InvokeRPCMethod($callId, $service, $method, $args)
    {
        /* We need the call data to encrypt. */
        $callobj = Array(
            'Service' => $service,
            'Method' => $method,
            'Id' => $callId,
            'Args' => $args
        );
        $requestData = json_encode(Array($callobj));
        $encrypted = $this->EncryptData($requestData);
        $this->transport->SendMessage($encrypted);

        $encryptedResponseData = $this->transport->ReadMessage();
        $responseData = $this->DecryptData($encryptedResponseData);
        return json_decode($responseData);
    }

    private function EncryptData($data)
    {
        $nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_NONCEBYTES);
        return $nonce . \Sodium\crypto_box($data, $nonce, $this->sessionKeypair);
    }

    private function DecryptData($data)
    {
        $nonce = substr($data, 0, \Sodium\CRYPTO_BOX_NONCEBYTES);
        $message = substr($data, \Sodium\CRYPTO_BOX_NONCEBYTES);
        return \Sodium\crypto_box_open($message, $nonce, $this->sessionKeypair);
    }
}

?>
