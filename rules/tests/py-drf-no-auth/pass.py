class SecureView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
