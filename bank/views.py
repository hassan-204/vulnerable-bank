from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from .models import Transaction, Profile, Cheque, ChequeActivation
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils.decorators import method_decorator
from django.views import View
from datetime import timedelta
from decimal import Decimal




def index(request):
    return render(request, 'index.html')


def market(request):
    # Get the top 10 users by balance in descending order
    top_users = Profile.objects.all().order_by('-balance')[:10]
    
    return render(request, 'market.html', {'top_users': top_users})



def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logout



def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        # Look for the user by email (Django uses username by default, so we override that here)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None

        if user is not None:
            # Attempt to authenticate the user using the email and password
            user = authenticate(request, username=user.username, password=password)
            
            if user is not None:
                login(request, user)
                messages.success(request, "You have successfully logged in.")
                return redirect('index')  # Redirect to your desired page after successful login
            else:
                messages.error(request, "Invalid email or password.")
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, 'login.html')



def register(request):
    if request.method == "POST":
        full_name = request.POST.get("name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm-password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect("register")
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already in use!")
            return redirect("register")

        # Create the user
        username = email.split('@')[0]  # Use part of the email as the username
        user = User.objects.create(
            username=username,
            email=email,
            first_name=full_name,
            password=make_password(password),  # Hash the password
        )
        user.save()
        messages.success(request, "Registration successful!")
        return redirect("login")  # Adjust the name of your login URL if needed
    
    return render(request, "register.html")




MAX_TRANSFER_LIMIT = Decimal('10000.00')  # Define the max transfer limit as Decimal
COOLDOWN_PERIOD = 30  # Cooldown period in seconds

@login_required
def transfer_funds(request):
    if request.method == "POST":
        recipient_username = request.POST.get('recipient')
        
        # Convert amount to Decimal to avoid float precision issues
        try:
            amount = Decimal(request.POST.get('amount'))
        except:
            messages.error(request, "Invalid amount.")
            return redirect('transfer_funds')

        # Get the logged-in user (sender)
        sender = request.user
        sender_profile = sender.profile  # Access the sender's profile to get balance

        # Ensure sender's balance is a Decimal
        sender_balance = Decimal(sender_profile.balance)

        # Check if recipient exists
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            messages.error(request, "Recipient not found.")
            return redirect('transfer_funds')

        # Check if recipient has a profile
        try:
            recipient_profile = recipient.profile
        except Profile.DoesNotExist:
            messages.error(request, "Recipient's profile not found.")
            return redirect('transfer_funds')

        # Check if amount is within limit
        if amount > MAX_TRANSFER_LIMIT or -amount > MAX_TRANSFER_LIMIT:
            messages.error(request, f"The transfer limit is {MAX_TRANSFER_LIMIT}.")
            return redirect('transfer_funds')

        # Check if sender has sufficient balance
        if sender_balance < amount and sender_balance > 0:
            messages.error(request, "Insufficient balance.")
            return redirect('transfer_funds')

        # Check for cooldown (last transaction)
        last_transaction = Transaction.objects.filter(sender=sender).order_by('-timestamp').first()
        if last_transaction and (timezone.now() - last_transaction.timestamp) < timedelta(seconds=COOLDOWN_PERIOD):
            messages.error(request, f"You must wait {COOLDOWN_PERIOD} seconds between transactions.")
            return redirect('transfer_funds')

        # Proceed with the transaction
        sender_profile.balance -= amount
        recipient_profile.balance += amount

        # Save the updated profiles
        sender_profile.save()
        recipient_profile.save()

        # Log the transaction
        Transaction.objects.create(sender=sender, recipient=recipient, amount=amount)

        messages.success(request, f"Successfully transferred {amount} to {recipient.username}.")
        return redirect('transfer_funds')

    return render(request, 'transfer_funds.html')





def deposit_cheque(request):
    if request.method == 'POST':
        cheque_code = request.POST.get('cheque_code')
        if len(cheque_code) != 16:
            messages.error(request, "Invalid cheque code length. It must be 16 digits.")
            return redirect('deposit_cheque')

        try:
            cheque = Cheque.objects.get(code=cheque_code, is_active=True)
        except Cheque.DoesNotExist:
            messages.error(request, "Invalid cheque code.")
            return redirect('deposit_cheque')

        # Check if the user has activated a cheque within the last 10 minutes
        last_activation = ChequeActivation.objects.filter(user=request.user).order_by('-activated_at').first()
        if last_activation and (timezone.now() - last_activation.activated_at).total_seconds() < 600:
            messages.error(request, "You can only activate one cheque every 10 minutes.")
            return redirect('deposit_cheque')

        # Create the cheque activation record
        ChequeActivation.objects.create(user=request.user, cheque=cheque)

        # Add the cheque amount to the user's balance
        request.user.profile.balance += cheque.amount
        request.user.profile.save()

        # Deactivate the cheque code to prevent re-use
        cheque.is_active = False
        cheque.save()

        messages.success(request, f"Cheque activated successfully. You received {cheque.amount}!")
        return redirect('deposit_cheque')
    
    return render(request, 'deposit_cheque.html')


# To ensure only superusers can access this page
def is_superuser(user):
    return user.is_superuser

# Admin Login View
def admin_login(request):
    if request.method == "POST":
        password = request.POST.get('password')

        # Here you would check if the password is correct (You can check with a predefined password for example)
        if password == "admin":  # Change to your desired password check logic
            request.session['password_verified'] = True
            return redirect('secret_question')  # Redirect to secret question page
        else:
            messages.error(request, "Incorrect password.")
            return render(request, 'admin_login.html')

    return render(request, 'admin_login.html')

# Secret Question View
def secret_question(request):
    if 'password_verified' in request.session:
        if request.method == "POST":
            answer = request.POST.get('answer')
            
            if answer.lower() == "venus":  # Check for the secret answer
                # Make the current user a superuser in the database
                user = request.user  # Get the logged-in user (this would be the user who logged in via admin_login)
                user.is_superuser = True
                user.is_staff = True  # Set is_staff to True to give them access to the admin panel
                user.save()

                request.session['is_admin'] = True  # Mark user as admin in the session
                return redirect('admin_dashboard')  # Redirect to the admin dashboard
            else:
                messages.error(request, "Incorrect answer to the secret question.")
                return render(request, 'secret_question.html')

        return render(request, 'secret_question.html')
    else:
        return redirect('admin_login')  # If password not verified, redirect to login


def admin_dashboard(request):
    if not request.session.get('is_admin', True):
        return redirect('admin_login')
    
    users = User.objects.all()
    return render(request, 'admin_dashboard.html', {'users': users})


from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, redirect
from django.contrib import messages

def transfer_funds_before_deletion(request, user_id):
    # Get the user to be deleted
    user_to_delete = User.objects.get(id=user_id)

    # Ensure the logged-in user is an admin (not trying to delete themselves or another admin)
    if request.user == user_to_delete:
        messages.error(request, "You cannot delete your own account.")
        return redirect('admin_dashboard')  # Redirect to admin dashboard if trying to delete their own account
    
    if user_to_delete.is_superuser:
        messages.error(request, "You cannot delete an admin account.")
        return redirect('admin_dashboard')  # Redirect to admin dashboard if trying to delete an admin's account
    
    # Check if the admin has reached the maximum allowed deletions (3)
    if request.session.get('deletion_count', 0) >= 2:
        messages.error(request, "You have reached the maximum number of deletions allowed (2).")
        return redirect('admin_dashboard')  # Redirect to admin dashboard if the limit is reached

    if request.method == 'POST':
        recipient_username = request.POST.get('recipient_username')
        
        try:
            recipient = User.objects.get(username=recipient_username)
        except ObjectDoesNotExist:
            messages.error(request, "Recipient username does not exist.")
            return redirect('transfer_funds_before_deletion', user_id=user_to_delete.id)
        
        # Ensure the user has funds to transfer (we'll assume a balance field exists in the user profile)
        if user_to_delete.profile.balance > 0:
            # Transfer funds
            recipient.profile.balance += user_to_delete.profile.balance
            recipient.profile.save()

            # Clear balance from the user to be deleted
            user_to_delete.profile.balance = 0
            user_to_delete.profile.save()

            # Now delete the user
            user_to_delete.delete()

            # Increment the deletion count
            request.session['deletion_count'] = request.session.get('deletion_count', 0) + 1

            messages.success(request, f"User {user_to_delete.username} deleted successfully.")
            return redirect('admin_dashboard')
        else:
            messages.error(request, "Insufficient funds to transfer.")
            return redirect('transfer_funds_before_deletion', user_id=user_to_delete.id)
    
    return render(request, 'transfer_funds_before_deletion.html', {'user': user_to_delete})



def dashboard(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('login')  # Redirect to login if not authenticated

    # Get user's balance and transactions
    balance = user.profile.balance  # Assuming balance is stored in the user's profile
    sent_transactions = Transaction.objects.filter(sender=user)
    received_transactions = Transaction.objects.filter(recipient=user)

    # Combine sent and received transactions into one list
    all_transactions = sent_transactions | received_transactions

    context = {
        "user": user,
        "balance": balance,
        "all_transactions": all_transactions,  # Pass the combined list
    }
    
    return render(request, "dashboard.html", context)



