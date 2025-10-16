from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import login as auth_login, logout as auth_logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authlib.integrations.django_client import OAuth
from django.conf import settings
import requests
import logging

logger = logging.getLogger(__name__)

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='auth0',
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    server_metadata_url=f'https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email'
    }
)

def home(request):
    return render(request, 'auth/home.html')

def login(request):
    redirect_uri = request.build_absolute_uri(reverse('callback'))
    print(redirect_uri)
    return oauth.auth0.authorize_redirect(request, redirect_uri)

def callback(request):
    token = oauth.auth0.authorize_access_token(request)
    user_info = token.get('userinfo')
    if user_info:
        # Create or update user (simplified, use your user model logic)
        user, _ = User.objects.get_or_create(
            username=user_info['sub'],
            defaults={'first_name': user_info.get('name', '')}
        )
        auth_login(request, user)
        request.session['user_info'] = user_info
    return redirect('home')

def logout(request):
    request.session.clear()
    auth_logout(request)
    return redirect(
        f'https://{settings.AUTH0_DOMAIN}/v2/logout?client_id={settings.AUTH0_CLIENT_ID}&returnTo={request.build_absolute_uri(reverse("home"))}'
    )

def detect_auth_provider(user_info):
    """
    Detect the authentication provider based on user_info.
    Returns 'google', 'github', or 'unknown'
    """
    # Check for Google-specific fields
    if 'iss' in user_info and 'accounts.google.com' in user_info['iss']:
        return 'google'
    
    # Check for GitHub-specific fields
    if 'github_username' in user_info or 'github_id' in user_info:
        return 'github'
    
    # Check domain patterns
    email = user_info.get('email', '')
    if email:
        # Google accounts typically have gmail.com or googlemail.com
        if any(domain in email for domain in ['gmail.com', 'googlemail.com']):
            return 'google'
        # GitHub accounts might have github.com in email or other patterns
        if 'github.com' in email:
            return 'github'
    
    # Check nickname patterns (GitHub usernames are often used as nicknames)
    nickname = user_info.get('nickname', '')
    if nickname and not email:  # If no email but has nickname, might be GitHub
        return 'github'
    
    return 'unknown'

def get_github_repositories(user_info):
    """
    Fetch GitHub repositories for the authenticated user.
    This function attempts to get repositories using the user's GitHub username.
    Note: This is a simplified implementation. In a production environment,
    you would need proper GitHub OAuth integration through Auth0.
    """
    try:
        # Extract GitHub username from user_info if available
        github_username = None
        
        # Try to get GitHub username from various possible fields
        if 'github_username' in user_info:
            github_username = user_info['github_username']
        elif 'nickname' in user_info:
            github_username = user_info['nickname']
        elif 'preferred_username' in user_info:
            github_username = user_info['preferred_username']
        elif 'login' in user_info:
            github_username = user_info['login']
        
        if not github_username:
            return []
        
        # Make request to GitHub API (public repositories only)
        github_url = f'https://api.github.com/users/{github_username}/repos'
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Auth0-Django-App'
        }
        
        response = requests.get(github_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            repos_data = response.json()
            repositories = []
            
            for repo in repos_data:
                repositories.append({
                    'name': repo.get('name', ''),
                    'full_name': repo.get('full_name', ''),
                    'description': repo.get('description', ''),
                    'html_url': repo.get('html_url', ''),
                    'language': repo.get('language', ''),
                    'stargazers_count': repo.get('stargazers_count', 0),
                    'forks_count': repo.get('forks_count', 0),
                    'updated_at': repo.get('updated_at', ''),
                    'private': repo.get('private', False)
                })
            
            return repositories
        else:
            logger.warning(f"GitHub API request failed with status {response.status_code}")
            return []
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching GitHub repositories: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error fetching GitHub repositories: {str(e)}")
        return []

class UserView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_info = request.session.get('user_info', {})
        
        # Detect authentication provider
        auth_provider = detect_auth_provider(user_info)
        
        # Prepare response data based on authentication provider
        if auth_provider == 'google':
            # For Google login: return first_name, last_name, email (no repositories)
            full_name = user_info.get('name', '').split(' ', 1)
            response_data = {
                'provider': 'google',
                'first_name': full_name[0] if len(full_name) > 0 else '',
                'last_name': full_name[1] if len(full_name) > 1 else '',
                'email': user_info.get('email', ''),
                'username': request.user.username
            }
        elif auth_provider == 'github':
            # For GitHub login: return email, username, and repositories
            repositories = get_github_repositories(user_info)
            response_data = {
                'provider': 'github',
                'username': request.user.username,
                'email': user_info.get('email', ''),
                'github_username': user_info.get('nickname', user_info.get('login', '')),
                'repositories': repositories,
                'repositories_count': len(repositories)
            }
        else:
            # For unknown provider: return basic info
            repositories = get_github_repositories(user_info) if user_info.get('nickname') else []
            response_data = {
                'provider': 'unknown',
                'username': request.user.username,
                'name': user_info.get('name', ''),
                'email': user_info.get('email', ''),
                'repositories': repositories,
                'repositories_count': len(repositories)
            }
        
        return Response(response_data)