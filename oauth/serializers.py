from rest_framework import serializers

class GoogleAuthSerializer(serializers.Serializer):
    gmail_address = serializers.EmailField()