<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class SchibstedAccount extends AbstractService
{
    private $environment;
    private $accessTokenEndpoint;
    private $acrValues = ['pwd'];

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        array $scopes = [],
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

        $this->environment = config('oauth-5-laravel.consumers.SchibstedAccount.environment','');
        $this->accessTokenEndpoint = config('oauth-5-laravel.consumers.SchibstedAccount.access_token_endpoint', '');
        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri($this->environment);
        }
    }

    /**
     * @param $responseBody
     * @return StdOAuth2Token
     *
     * @throws TokenResponseException
     */
    protected function parseAccessTokenResponse($responseBody): StdOAuth2Token
    {
        $data = json_decode($responseBody, true);

        if (!is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        }

        if (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifeTime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token'], $data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    protected function getAuthorizationMethod(): int
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    public function isValidScope($scope): bool
    {
        return true;
    }

    public function setACRValues($acrValues): void
    {
        $this->acrValues = $acrValues;
    }

    public function getAuthorizationEndpoint(): Uri
    {
        $uri = new Uri($this->environment . 'oauth/authorize');

        $uri->addToQuery('new-flow', 'true');
        $uri->addToQuery('acr_values', implode(' ', $this->acrValues));

        return $uri;
    }

    public function getAccessTokenEndpoint(): Uri
    {
        return new Uri($this->accessTokenEndpoint);
    }

    public function getLogoutUrl($returnTo = null): Uri
    {
        $returnTo = is_null($returnTo) ? \URL::current() : $returnTo;

        $uri = new Uri($this->environment . 'logout');
        $uri->addToQuery('client_id', $this->credentials->getConsumerId());
        $uri->addToQuery('redirect_uri', $returnTo);

        return $uri;
    }
}
