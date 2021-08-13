package com.kb.demo;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SimpleController {

    @GetMapping("/test")
    public String getResp(Principal principal){
        return  principal.getName();
    }

    @GetMapping("/callback")
    public Object code(@RequestParam(value = "code", required = false) String code) throws UnirestException {
        Unirest.setTimeouts(0, 0);
        return Unirest.post("https://*.auth.us-east-1.amazoncognito.com/oauth2/token")
                .header("Authorization", "Basic *")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .field("grant_type", "authorization_code")
                .field("redirect_uri", "http://localhost:8080/callback")
                .field("code", code)
                .asString().getBody();
    }

    @GetMapping("/create")
    public void createUser() {
        String userPoolId = "*";
        String username = "*";
        String email = "*";
        String password = "*";

        //AWS credentials
        String ACCESS_KEY = "*";
        String SECRET_KEY = "*";

        BasicAWSCredentials awsCreds = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);

        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder
                .standard().withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withRegion("us-east-1").build();

        try {
            AttributeType emailAttr = new AttributeType().withName("email").withValue(email);
            AttributeType emailVerifiedAttr =
                    new AttributeType().withName("email_verified").withValue("false");

            AdminCreateUserRequest userRequest =
                    new AdminCreateUserRequest().withUserPoolId(userPoolId).withUsername(username)
                            .withTemporaryPassword(password)
                            .withUserAttributes(emailAttr, emailVerifiedAttr)
                            .withMessageAction(MessageActionType.SUPPRESS);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(userRequest);

            System.out.println("User " + createUserResult.getUser().getUsername()
                    + " is created. Status: " + createUserResult.getUser().getUserStatus());

            // Make the password permanent and not temporary
            AdminSetUserPasswordRequest adminSetUserPasswordRequest =
                    new AdminSetUserPasswordRequest().withUsername(username)
                            .withUserPoolId(userPoolId).withPassword(password).withPermanent(true);
            cognitoClient.adminSetUserPassword(adminSetUserPasswordRequest);
        } catch (AWSCognitoIdentityProviderException e) {
            System.out.println(e.getErrorMessage());
        } catch (Exception e) {
            System.out.println(e);
        }

    }

}
