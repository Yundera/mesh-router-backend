# serviceAccount.json

Firebase Admin SDK service account credentials for server-side operations.

## Where to Get It

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project
3. Click the gear icon (Project Settings)
4. Go to "Service accounts" tab
5. Click "Generate new private key"
6. Rename the downloaded file to `serviceAccount.json`

## Example Structure

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "abc123...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-xxxxx@your-project.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}
```

## Important Notes

- This file contains **sensitive credentials** - never commit to version control
- Keep this file in the `config/` directory
- Ensure the service account has Firestore access permissions
