using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;

public class UIThings : MonoBehaviour
{
    public Button SignupButton;
    public Button SignInButton;
    public InputField EmailField;
    public InputField PasswordField;
    public Text StatusText;


    // Use this for initialization
    void Start () {
        SignupButton.onClick.AddListener(on_signup_click);
        SignInButton.onClick.AddListener(on_signin_click);
    }
	
	// Update is called once per frame
	void Update () {
		
	}


    CognitoThings Cognito {
        get {
            if (_cognito == null)
                _cognito = GameObject.Find("AWSCognito").GetComponent<CognitoThings>();
            return _cognito;
        }
    }
    CognitoThings _cognito = null;


    public void on_signup_click()
    {
        string email = EmailField.text;
        string password = PasswordField.text;
        Cognito.TrySignupRequest(email, password,
            () => { StatusText.text = "Failed! Check the log."; },
            () => { StatusText.text = "Success! Check your email to confirm!."; }
        );
    }

    public void on_signin_click()
    {
        string email = EmailField.text;
        string password = PasswordField.text;
        Cognito.TrySignInRequest(email, password,
            () => { StatusText.text = "Failed! Check the log."; },
            (token) => { StatusText.text = "Success! Token is " + token.Substring(0,10) + "..."; }
        );
    }


}
