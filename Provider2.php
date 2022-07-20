<?php

namespace SocialiteProviders\Slack;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Psr\Http\Message\ResponseInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider2 extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'SLACK2';

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $userScopes = [];

    /**
     * Set the user scopes of the requested access.
     *
     * @param  array|string  $scopes
     * @return $this
     */
    public function setUserScopes($scopes)
    {
        $this->userScopes = array_unique((array) $scopes);

        return $this;
    }

    /**
     * Get the current user scopes.
     *
     * @return array
     */
    protected function getUserScopes()
    {
        // Provide some default scopes if the user didn't define some.
        // See: https://github.com/SocialiteProviders/Providers/pull/53
        if (count($this->userScopes) === 0 && count($this->scopes) === 0) {
            return ['identity.basic', 'identity.email', 'identity.team', 'identity.avatar'];
        }

        return $this->userScopes;
    }

    /**
     * Middleware that throws exceptions for non successful slack api calls
     * "http_error" request option is set to true.
     *
     * @return callable Returns a function that accepts the next handler.
     */
    private function getSlackApiErrorMiddleware()
    {
        return function (callable $handler) {
            return function ($request, array $options) use ($handler) {
                if (empty($options['http_errors'])) {
                    return $handler($request, $options);
                }

                return $handler($request, $options)->then(
                    function (ResponseInterface $response) use ($request) {
                        $body = json_decode($response->getBody()->getContents(), true);
                        $response->getBody()->rewind();

                        if ($body['ok']) {
                            return $response;
                        }

                        throw RequestException::create($request, $response);
                    }
                );
            };
        };
    }

    /**
     * {@inheritdoc}
     */
    protected function getHttpClient()
    {
        $handler = HandlerStack::create();
        $handler->push($this->getSlackApiErrorMiddleware(), 'slack_api_errors');

        if (is_null($this->httpClient)) {
            $this->httpClient = new Client(['handler' => $handler]);
        }

        return $this->httpClient;
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://slack.com/oauth/v2/authorize',
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://slack.com/api/oauth.v2.access';
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'user_scope' => $this->formatScopes($this->getUserScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'granular_bot_scope' => true,
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        if ($this->usesPKCE()) {
            $fields['code_challenge'] = $this->getCodeChallenge();
            $fields['code_challenge_method'] = $this->getCodeChallengeMethod();
        }

        return array_merge($fields, $this->parameters);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessToken($body)
    {
        return Arr::get($body, 'authed_user.access_token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        Log::debug('token', [$token]);
        try {
            $response = $this->getHttpClient()->get(
                'https://slack.com/api/users.identity',
                [
                    'headers' => [
                        'Authorization' => 'Bearer '.$token,
                    ],
                ]
            );
        } catch (RequestException $exception) {
            // Getting user informations requires the "identity.*" scopes, however we might want to not add them to the
            // scope list for various reasons. Instead of throwing an exception on this error, we return an empty user.

            if ($exception->hasResponse()) {
                $data = json_decode($exception->getResponse()->getBody(), true);

                if (Arr::get($data, 'error') === 'missing_scope') {
                    return [];
                }
            }

            throw $exception;
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'              => Arr::get($user, 'user.id'),
            'name'            => Arr::get($user, 'user.name'),
            'email'           => Arr::get($user, 'user.email'),
            'avatar'          => Arr::get($user, 'user.image_192'),
            'organization_id' => Arr::get($user, 'team.id'),
        ]);
    }
}
