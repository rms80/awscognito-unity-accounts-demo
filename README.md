# awscognito-unity-accounts-demo

This is a fully-functional Unity project (Unity 2017.3, using .NET 4.5) that demonstrates sign-up and sign-in for AWS Cognito user accounts. This is not (Jan 2018) supported by the official AWS SDK release. I have rebuilt the SDK using [this fork](https://github.com/rms80/aws-sdk-net), DLLs are included. 

See this tutorial for instructions on how to set up the AWS side, and things you need to do in the code to make it work: http://www.gradientspace.com/tutorials/2018/1/25/using-aws-cognito-user-accounts-with-unity

The Sign-in code, and particularly the math parts, are borrowed from this article by Marcus Lachinger: http://blog.mmlac.com/aws-cognito-srp-login-c-sharp-dot-net/. His github is here: https://github.com/mmlac

Also using the Hkdf class from this gist: https://gist.github.com/CodesInChaos/8710228

Also includes a complied [BouncyCastle](https://www.bouncycastle.org/) dll, if you want to rebuild from source, it is here: https://github.com/bcgit/bc-csharp

My code is released under MIT license, but these other things, have their own licenses.
