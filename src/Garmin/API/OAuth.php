<?php
namespace Garmin\API;

use League\OAuth1\Client\Server\Server;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use League\OAuth1\Client\Credentials\CredentialsException;
use League\OAuth1\Client\Credentials\CredentialsInterface;
use League\OAuth1\Client\Credentials\TemporaryCredentials;
use League\OAuth1\Client\Credentials\TokenCredentials;
use League\OAuth1\Client\Server\User;

/**
 * Garmin OAuth
 * The Garmin implementation of the OAuth client
 *
 * Based off of code by Mustapha:
 * (https://github.com/stoufa06/php-garmin-connect-api)
 *
 * @see: https://github.com/thephpleague/oauth2-client
 * @author James Van Hinsbergh
 */
class OAuth extends Server
{
    /**
     * URL for the Garmin Connect endpoint
     */
    const API_URL = "https://connectapi.garmin.com/";

    /**
     * URL for the Garmin REST API endpoint
     */
    const USER_API_URL = "https://healthapi.garmin.com/wellness-api/rest/";

    /**
     * Get the URL for retrieving temporary credentials.
     *
     * @return string
     */
    public function urlTemporaryCredentials(): string
    {
        return self::API_URL . 'oauth-service/oauth/request_token';
    }

    /**
     * Get the URL for redirecting the resource owner to authorize the client.
     *
     * @return string
     */
    public function urlAuthorization(): string
    {
        return 'http://connect.garmin.com/oauthConfirm';
    }

    /**
     * Get the URL retrieving token credentials.
     *
     * @return string
     */
    public function urlTokenCredentials(): string
    {
        return self::API_URL . 'oauth-service/oauth/access_token';
    }

    /**
     * Get the authorization URL by passing in the temporary credentials
     * identifier or an object instance.
     *
     * @param TemporaryCredentials|string $temporaryIdentifier
     * @return string
     */
    public function getAuthorizationUrl($temporaryIdentifier): string
    {
        // Somebody can pass through an instance of temporary
        // credentials and we'll extract the identifier from there.
        if ($temporaryIdentifier instanceof TemporaryCredentials) {
            $temporaryIdentifier = $temporaryIdentifier->getIdentifier();
        }

        $url = $this->urlAuthorization();
        $queryString = "oauth_token=" . $temporaryIdentifier . "&oauth_callback=" . $this->clientCredentials->getCallbackUri();

        return $this->buildUrl($url, $queryString);
    }

    /**
     * Retrieves token credentials by passing in the temporary credentials,
     * the temporary credentials identifier as passed back by the server
     * and finally the verifier code.
     *
     * @param TemporaryCredentials $temporaryCredentials
     * @param string $temporaryIdentifier
     * @param string $verifier
     * @return TokenCredentials
     * @throws CredentialsException If a "bad response" is received by the server
     * @throws GuzzleException
     * @throws InvalidArgumentException
     */
    public function getTokenCredentials(TemporaryCredentials $temporaryCredentials, string $temporaryIdentifier, string $verifier): TokenCredentials
    {
        if ($temporaryIdentifier !== $temporaryCredentials->getIdentifier()) {
            throw new InvalidArgumentException(
                'Temporary identifier passed back by server does not match that of stored temporary credentials.
                Potential man-in-the-middle.'
            );
        }

        $uri = $this->urlTokenCredentials();
        $bodyParameters = array('oauth_verifier' => $verifier);

        $client = $this->createHttpClient();

        $headers = $this->getHeaders($temporaryCredentials, 'POST', $uri, $bodyParameters);
        try {
            $response = $client->post($uri, [
                'headers' => $headers,
                'form_params' => $bodyParameters
            ]);
        } catch (BadResponseException $e) {
            throw $this->getCredentialsExceptionForBadResponse($e, 'token credentials');
        }

        return $this->createTokenCredentials((string) $response->getBody());
    }

    /**
     * Generate the OAuth protocol header for requests other than temporary
     * credentials, based on the URI, method, given credentials & body query
     * string.
     *
     * @param string $method
     * @param string $uri
     * @param CredentialsInterface $credentials
     * @param array $bodyParameters
     * @return string
     */
    protected function protocolHeader(string $method, string $uri, CredentialsInterface $credentials, array $bodyParameters = array()): string
    {
        $parameters = array_merge(
            $this->baseProtocolParameters(),
            $this->additionalProtocolParameters(),
            array(
                'oauth_token' => $credentials->getIdentifier(),

            ),
            $bodyParameters
        );
        $this->signature->setCredentials($credentials);

        $parameters['oauth_signature'] = $this->signature->sign(
            $uri,
            array_merge($parameters, $bodyParameters),
            $method
        );

        return $this->normalizeProtocolParameters($parameters);
    }

    /**
     * Send a HTTP delete request to revoke the user's access token
     *
     * @param TokenCredentials $tokenCredentials
     * @return void
     * @throws Exception
     */
    public function revokeToken(TokenCredentials $tokenCredentials): void
    {
        $uri = 'user/registration';
        $client = $this->createHttpClient();
        $headers = $this->getHeaders($tokenCredentials, 'DELETE', self::USER_API_URL . $uri);

        try {
            $response = $client->delete(self::USER_API_URL . $uri, [
                'headers' => $headers,
            ]);
        } catch (BadResponseException $e) {
            $response = $e->getResponse();
            $body = $response->getBody();
            $statusCode = $response->getStatusCode();

            throw new \Exception(
                "Received error [$body] with status code [$statusCode] when deleting user access token."
            );
        }
    }

    /**
     * returns user details url
     *
     * @return string
     */
    public function urlUserDetails(): string
    {
        return self::USER_API_URL . 'user/id';
    }

    /**
     * get user details: in garmin there is only user id
     *
     * @param mixed $data
     * @param TokenCredentials $tokenCredentials
     * @return User
     */
    public function userDetails($data, TokenCredentials $tokenCredentials): User
    {
        $user = new User();

        $user->uid = $data['userId'];


        $user->extra = (array) $data;

        return $user;
    }

    /**
     * get user id
     *
     * @param mixed $data
     * @param TokenCredentials $tokenCredentials
     * @return string|int|null
     */
    public function userUid($data, TokenCredentials $tokenCredentials)
    {
        return isset($data['userId']) ? $data['userId'] : null;
    }

    /**
     * Left for compatibilty
     *
     * @param mixed $data
     * @param TokenCredentials $tokenCredentials
     * @return string return empty string
     */
    public function userEmail($data, TokenCredentials $tokenCredentials): string
    {
        return '';
    }

    /**
     * Left for compatibilty
     *
     * @param mixed $data
     * @param TokenCredentials $tokenCredentials
     * @return string return empty string
     */
    public function userScreenName($data, TokenCredentials $tokenCredentials): string
    {
        return '';
    }

    /**
     * Send a request to backfill summary type
     *
     * @param TokenCredentials $tokenCredentials
     * @param string $uri
     * @param array $params
     * @return void
     * @throws Exception
     */
    public function backfill(TokenCredentials $tokenCredentials, string $uri, array $params): void
    {
        $client = $this->createHttpClient();
        $query = http_build_query($params);
        $query = 'backfill/'.$uri.'?'.$query;
        $headers = $this->getHeaders($tokenCredentials, 'GET', self::USER_API_URL . $query);

        try {
            $response = $client->get(self::USER_API_URL . $query, [
                'headers' => $headers,
            ]);
        } catch (BadResponseException $e) {
            $response = $e->getResponse();
            $body = $response->getBody();
            $statusCode = $response->getStatusCode();

            throw new \Exception(
                "Received error [$body] with status code [$statusCode] when requesting historic $uri summary."
            );
        }
    }

    /**
     * Send a request to backfill activity summary
     *
     * @param TokenCredentials $tokenCredentials
     * @param array $params
     * @return void
     * @throws Exception
     */
    public function backfillActivitySummary(TokenCredentials $tokenCredentials, array $params): void
    {
        $this->backfill($tokenCredentials, 'activities', $params);
    }
}