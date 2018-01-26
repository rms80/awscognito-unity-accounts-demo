using System;
using System.Collections.Generic;
using System.Globalization;
using UnityEngine;

using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Runtime;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;


public class CognitoThings : MonoBehaviour
{
    // All these settings are found in the User Pool page on AWS Management Console
    public const string AppClientID = "YOUR_APP_CLIENT_ID_GOES_HERE";       // find this under "App Client Settings"
    public const string UserPoolId = "us-east-2_USERPOOLID";                // Pool Id on the General Settings page
    public const string UserPoolName = "USERPOOLID";                        // the bit at the end of UserPoolID, after the region
    RegionEndpoint CognitoIdentityRegion = RegionEndpoint.USEast1;


    void Start () {
        // this is an AWS thing
        UnityInitializer.AttachToGameObject(this.gameObject);

        // seems like this is necessary for Unity 2017: https://github.com/aws/aws-sdk-net/issues/643
        AWSConfigs.HttpClient = AWSConfigs.HttpClientOption.UnityWebRequest;
    }
	

    /// <summary>
    /// Cognito IDP Client is constructed on-demand
    /// </summary>
    private AmazonCognitoIdentityProviderClient CognitoIDPClient {
        get {
            if (_cgClient == null) {
                var config = new AmazonCognitoIdentityProviderConfig();
                config.RegionEndpoint = CognitoIdentityRegion;
                _cgClient = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), config);
            }
            return _cgClient;
        }
    }
    private AmazonCognitoIdentityProviderClient _cgClient = null;




    /// <summary>
    /// Try to sign up with given email & password.
    /// </summary>
    public void TrySignupRequest(string email, string password,
        Action OnFailureF = null, Action OnSuccessF = null)
    {
        SignUpRequest signUpRequest = new SignUpRequest() {
            ClientId = AppClientID,
            Password = password,
            Username = email,
        };
        var emailAttribute = new AttributeType {
            Name = "email", Value = email
        };
        signUpRequest.UserAttributes.Add(emailAttribute);

        Debug.Log("posting signup request...");

        CognitoIDPClient.SignUpAsync(signUpRequest, (response) => {
            if (response.Exception == null) {
                Debug.Log("[TrySignupRequest] signup request completed");
                if (OnSuccessF != null)
                    OnSuccessF();

            } else {
                Debug.Log("[TrySignupRequest] signup request exception : " + response.Exception.ToString());
                if (OnFailureF != null)
                    OnFailureF();
            }
        });
    }




    /// <summary>
    /// Try to sign in with email and password
    /// </summary>
    public void TrySignInRequest(string username, string password,
        Action OnFailureF = null, Action<string> OnSuccessF = null)
    {
        //Get the SRP variables A and a
        var TupleAa = AuthenticationHelper.CreateAaTuple();

        InitiateAuthRequest authRequest = new InitiateAuthRequest() {
            ClientId = AppClientID,
            AuthFlow = AuthFlowType.USER_SRP_AUTH,
            AuthParameters = new Dictionary<string, string>() {
                    { "USERNAME", username },
                    { "SRP_A", TupleAa.Item1.ToString(16) } }
        };

        //
        // This is a nested request / response / request. First we send the
        // InitiateAuthRequest, with some crypto things. AWS sends back
        // some of its own crypto things, in the authResponse object (this is the "challenge").
        // We combine that with the actual password, using math, and send it back (the "challenge response").
        // If AWS is happy with our answer, then it is convinced we know the password,
        // and it sends us some tokens!
        CognitoIDPClient.InitiateAuthAsync(authRequest, (authResponse) => {
            if (authResponse.Exception != null) {
                Debug.Log("[TrySignInRequest] exception : " + authResponse.Exception.ToString());
                if (OnFailureF != null)
                    OnFailureF();
                return;
            }

            //The timestamp format returned to AWS _needs_ to be in US Culture
            DateTime timestamp = TimeZoneInfo.ConvertTimeToUtc(DateTime.Now);
            CultureInfo usCulture = new CultureInfo("en-US");
            String timeStr = timestamp.ToString("ddd MMM d HH:mm:ss \"UTC\" yyyy", usCulture);

            //Do the hard work to generate the claim we return to AWS
            var challegeParams = authResponse.Response.ChallengeParameters;
            byte[] claim = AuthenticationHelper.authenticateUser( 
                                challegeParams["USERNAME"],
                                password, UserPoolName, TupleAa,
                                challegeParams["SALT"], challegeParams["SRP_B"], 
                                challegeParams["SECRET_BLOCK"], timeStr);

            String claimBase64 = System.Convert.ToBase64String(claim);

            // construct the second request
            RespondToAuthChallengeRequest respondRequest = new RespondToAuthChallengeRequest() {
                ChallengeName = authResponse.Response.ChallengeName,
                ClientId = AppClientID,
                ChallengeResponses = new Dictionary<string, string>() {
                            { "PASSWORD_CLAIM_SECRET_BLOCK", challegeParams["SECRET_BLOCK"] },
                            { "PASSWORD_CLAIM_SIGNATURE", claimBase64 },
                            { "USERNAME", username },
                            { "TIMESTAMP", timeStr } }
            };

            // send the second request
            CognitoIDPClient.RespondToAuthChallengeAsync(respondRequest, (finalResponse) => {
                if (finalResponse.Exception != null) {
                    // Note: if you have the wrong username/password, you will get an exception.
                    // It's up to you to differentiate that from other errors / etc.
                    Debug.Log("[TrySignInRequest] exception : " + finalResponse.Exception.ToString());
                    if (OnFailureF != null)
                        OnFailureF();
                    return;
                }

                // Ok, if we got here, we logged in, and here are some tokens
                AuthenticationResultType authResult = finalResponse.Response.AuthenticationResult;
                string idToken = authResult.IdToken;
                string accessToken = authResult.AccessToken;
                string refreshToken = authResult.RefreshToken;

                Debug.Log("[TrySignInRequest] success!");
                if (OnSuccessF != null)
                    OnSuccessF(idToken);
            });


        });   // end of CognitoIDPClient.InitiateAuthAsync

    }



}
