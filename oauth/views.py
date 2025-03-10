from django.shortcuts import render

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from oauth.oauth_flow import GmailOAuthHandler
from oauth.serializers import GoogleAuthSerializer

class AuthCodeView(APIView):
    def get(self, request):
        print(request.query_params)
        params = request.query_params
        code_dict = params.dict()
        print("CODE_DICT", code_dict, "\n\n\n\n\n")
        state = code_dict.get("state")
        code = code_dict.get("code")

        try:
            oauth_handler = GmailOAuthHandler()
            token_data = oauth_handler.fetch_tokens(authorization_code=code)
        except Exception as e:
            return Response(
                {
                    "message": "An error occurred!",
                    "error": str(e) 
                }
            )

        return Response(
                {
                    "message": "Successful!",
                    "token_data": token_data,
                    "state": state,
                    "code": code,
                }, status=status.HTTP_200_OK
            )


class GetAuthUrlView(APIView):
    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer_data = serializer.validated_data

        gmail_address = serializer_data.get("gmail_address")
        
        try:
            oauth_handler = GmailOAuthHandler()
            auth_url = oauth_handler.get_authorization_url(gmail_address)
            
            return Response(
                {
                    "authorization_url": auth_url,
                }, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {
                    "message": "OAuth2 flow failed!",
                    "error": str(e),
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )