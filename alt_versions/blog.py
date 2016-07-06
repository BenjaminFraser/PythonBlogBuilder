import os
import re
import string
import random
import hashlib
import hmac
from string import letters
import logging
import json
import webapp2
import jinja2

from google.appengine.ext import ndb
from models import User, Post

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# obtain client id for Google Login functionality.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# set global variable session for template session data accessibility.
jinja_env.globals['session'] = {}

# Cookie securing functionality
SECRET = 'ddvtohCUzsOsd5RkZInx5ehUVpuzrZKvlrdXUdPk'

def make_hash_str(input_val):
    return hmac.new(SECRET, input_val).hexdigest()

def make_secure_val(input_val):
    # use "|" rather than ",", since GAE does not support "," within its cookies.
    return "{0}|{1}".format(str(input_val), make_hash_str(input_val))

def verify_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if str(make_secure_val(val)) == str(secure_val):
        return val

def fetch_username(user_id):
    """Returns a User entities username from a given user_id
    Args:
        user_id: the unique user_id corresponding to the given user in Datastore.
    Returns:
        The given user's username as a string if it exists, else returns NoneType object.
    """
    user = ndb.Key(User, int(user_id)).get()
    logging.info("The username of the user is: {0}".format(user.username))
    return user and user.username

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# BlogHandler class to carry out the methods required by our blog.
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, value):
        """Sets a secure cookie value using the make_secure_val function and GAE
            headers.add_header().
        Args:
            name: The name the cookie value is given.
            value: The value the cookie is to be given.
        """
        secure_val = make_secure_val(value)
        self.response.headers.add_header('Set-Cookie', 
                                             '{0}={1}; Path=/'.format(name, secure_val))

    def get_verified_cookie(self, name):
        """Validates and returns a cookie value if it is legitimate
        Args:
            name: the name of the cookie that is to be read.
        Returns:
            The verified cookie value, as a string, without the hash value, provided the cookie 
            is valid and the cookie original value matches its hash value. 
        """
        cookie_val = self.request.cookies.get(name)
        # return using 'and' as a safeguard; only return the second val if the fist is true.
        return cookie_val and verify_secure_val(cookie_val)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.set_session()


    def login(self, user_id_str):
        self.set_cookie('user_id', user_id_str)

    def initialize(self, *args, **kwargs):
        """An initialize function that gets run during every request. The user_id is stored within 
             self.user after every request, to prevent repetitive fetching of the user_id cookie.
        Args:
            *args: Any number of positional arguments given as parameters.
            **kwargs: Any number of keyword arguments given as parameters to the function.
        """
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        user_id = self.get_verified_cookie('user_id')
        # set self.user to the user, provided it exists and is valid
        self.user = user_id and User.fetch_by_id(int(user_id))
        if self.user:
            self.set_session(self.user)

    def set_session(self, user=None):
        """A function that passes general user information to the session global variable 
            within the jinja2 environment, so that it is available within templates.
        Args:
            user: The Datastore User entity of the currently logged in user.
        """
        if not user:
            jinja_env.globals['session'] = {}
        else:
            jinja_env.globals['session'].update({ 'id': user.key.id(),
                                                  'username' : user.username, 
                                                  'email' : user.email })

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.render('introduction.html')

##### blog stuff
def blog_key(name = 'default'):
    """An ancestor element key function for blogs within the Datastore. Various
        groups can be created for different names of blogs, 'default' by default.
    """
    return ndb.Key('blogs', name)

# User account functionality
def make_salt(length=5):
    """Creates a random salt value of length 5 by default. If an integer is given as an arg,
        a salt of the corresponding length will be generated and returned.
    Args:
        length (int): The length of the desired salt value, 5 by default.
    Returns:
        The generated salt value, as a string.
    """
    return ''.join(random.choice(string.letters+string.digits) for x in range(length))

def make_password_hash(name, password, salt=None):
    """Creates a secure password hash given a User name and password given as string arguments.
        A custom salt can be used through using the 'salt' keyword variable, equal to desired salt.
    Args:
        name (str): The User username, as a string.
        password (str): the User password, as a string.
        salt (str): The desired salt to be used within the password hash. None by default, in which case
                    a random salt of length 5 is used.
    Returns:
        The secure hash, in the form of a string, like so: "hash_value, salt_value"
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(str(name) + str(password) + salt).hexdigest()
    return "{0},{1}".format(h, salt)

def valid_user_password(name, password, hash_val):
    """Takes a Users name, password and database hash_val and verifies that the user login
        details were valid.
    Args:
        name (str): The username of the User, as a string.
        password (str): The password entered by the user, as a string.
        hash_val (str): The hash value from the Datastore, as a string.
    Returns:
        True if the password and username credentials are valid, else returns False.
    """
    salt = hash_val.split(",")[1]
    return True if make_password_hash(name, password, salt) == hash_val else False

def users_key(group= 'default'):
    """An ancestor element key function for users within the Datastore. Various
        groups can be created for different kinds of users, 'default' by default.
    """
    return ndb.Key('users', group)

class BlogFront(BlogHandler):
    def get(self):
        posts = ndb.gql("select * from Post order by created desc limit 10")
        user_message = jinja_env.globals['session'].get('notification')
        # reset the session notification global value to None.
        jinja_env.globals['session']['notification'] = None
        self.render('front.html', posts = posts, user_message=user_message)

class PostPage(BlogHandler):
    def get(self, urlsafe_postkey):
        post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
        if not post:
            self.error(404)
            return
        user_message = None
        # if GET request received for post, which matches creator name, like post.
        if self.request.get('like_status') and self.request.get('target_user'):
            if self.user and self.request.get('like_status') == "like":
                user = User.fetch_by_id(self.user.key.id())
                user.like_post(urlsafe_postkey)
                user_message = {'title' : 'Thanks!',
                                'text' : 'You liked this post.',
                                'image' : 'thumbs-up.jpg'
                                }
            if self.user and self.request.get('like_status') == "dislike":
                user = User.fetch_by_id(self.user.key.id())
                user.dislike_post(urlsafe_postkey)
                user_message = {'title' : 'Thanks!',
                                'text' : 'This post has been disliked.',
                                'image' : 'thumbs-up.jpg'
                                }
        if self.user and self.user.username == post.creator:
            creator=True
            return self.render("permalink.html", post=post,
                                creator=creator, user_message=user_message)
        else:
            return self.render("permalink.html", post=post, 
                                creator=False, user_message=user_message)

class UserPosts(BlogHandler):
    """Displays all of a users created posts."""
    def get(self, user_id):
        if self.user:
            user_posts = Post.query_post(self.user.key).fetch()
            # fetch all user liked/disliked posts using the User liked_post_keys string list.
            liked_keys = [ndb.Key(urlsafe=i) for i in self.user.liked_post_keys[-10:]]
            disliked_keys = [ndb.Key(urlsafe=i) for i in self.user.disliked_post_keys[-10:]]
            liked_posts = ndb.get_multi(liked_keys)
            disliked_posts = ndb.get_multi(disliked_keys)
            followed_keys = [ndb.Key(urlsafe=i) for i in self.user.followed_user_keys[:25]]
            followers = ndb.get_multi(followed_keys)
            return self.render("userposts.html", user_posts=user_posts, 
                            liked_posts=liked_posts, followers=followers)
        else: 
            self.redirect("/login")

class NewPost(BlogHandler):
    def get(self, user_id):
        if self.user and int(self.user.key.id()) == int(user_id):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self, user_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=self.user.key, subject = subject, 
                        content = content, creator = self.user.username)
            p.put()
            # create a urlsafe version of the key and pass into URL.
            self.redirect('/blog/%s' % str(p.key.urlsafe()))
        else:
            alert_message = { 'title' : "Whoops!", 
                      'text' : "You need to fill in both subject and content!",
                      'type' : "error" }
            self.render("newpost.html", subject=subject, 
                            content=content, alert_message=alert_message)

#exceptions to be added to this class.
class EditPost(BlogHandler):
    def get(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                self.render('editpost.html', post=post)
            else:
                error = "You must be the post owner in order to edit!"
                self.redirect("/blog/{0}".format(str(urlsafe_postkey)))
        else:
            self.redirect("/login")

    def post(self, urlsafe_postkey):
        post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
        if not post:
            self.error(404)
            return
        if self.user and self.user.username == post.creator:
            new_subject = self.request.get('subject')
            new_content = self.request.get('content-area')
            post.subject = str(new_subject)
            post.content = str(new_content)
            logging.error("Added %s, %s to the blog post." % (new_content, new_subject))
            post.put()
            jinja_env.globals['session']['notification'] = { 
                                                    'title' : 'Thanks {0}'.format(self.user.username),
                                                    'text' : 'Your blog post has been successfully updated.',
                                                    'image' : 'thumbs-up.jpg'}
            self.redirect("/blog")

        else:
            self.redirect("/blog/{0}".format(str(urlsafe_postkey)))

# exceptions to be added to this class
class DeletePost(BlogHandler):
    def get(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                self.render('deletepost.html', post=post)
            else:
                self.redirect("/blog")
        else:
            self.redirect("/login")

    def post(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                delete_request = self.request.get('deletePost')
                if delete_request == "yes":
                    post.key.delete()
                    jinja_env.globals['session']['notification'] = { 
                                                    'title' : 'Thanks {0}'.format(self.user.username),
                                                    'text' : 'Your blog post has been successfully deleted.',
                                                    'image' : 'thumbs-up.jpg'
                                                    }
                    self.redirect("/blog")
                elif delete_request == "no":
                    self.redirect("/blog/{0}".format(str(post_id)))
                else:
                    self.redirect("/blog/{0}".format(str(post_id)))
            else:
                self.redirect("/login")
        else:
            self.redirect("/login")


###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        # obtain any user_messages passed into the notification var, and reset to None.
        alert_message = jinja_env.globals['session'].get('notification')
        jinja_env.globals['session']['notification'] = None
        self.render("signup_glogin.html", alert_message=alert_message)

    def post(self):
        have_error = False
        username = str(self.request.get('username')).capitalize()
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        # check for an existing username with the same name, if so, insert error
        q = User.query()
        q = q.filter(User.username == username).get()
        if q:
            params['error_name_taken'] = "That username is already taken!"
            have_error = True

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            user = User.new_user(username=username, password=password, email=email)
            user.put()
            self.login(str(user.key.id()))
            #id_str = str(user.key.id())
            #self.set_cookie('user_id', str(user.key.id()))
            #self.response.headers.add_header('Set-Cookie', 
            #                                'user_id={0}'.format(make_secure_val(id_str)))
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        # Generate a unique random session state variable as a secure token.
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        jinja_env.globals['session']['state'] = state
        self.render('login.html', STATE=state)

    def post(self):
        have_error = False
        username = str(self.request.get('username')).capitalize()
        password = self.request.get('password')

        params = dict(username = username)

        # attempt to fetch the user corresponding to the username from the database.
        user = User.fetch_by_username(username) 
        # generate an error message if user does not exist.
        if not user:
            have_error = True
            params['error_username'] = "We couldn't find a user with that username."
            if not password:
                have_error = True
                params['error_password'] = "You need to enter a password!"
        # if user does exist, validate the given password against the User password hash.
        else:
            pass_val = valid_user_password(username, password, str(user.pass_hash))
            if not pass_val:
                have_error = True
                params['error_password'] = "The password you entered was incorrect."

        if have_error:
            self.render('login.html', **params)
        else:
            # simulate login by setting the user_id cookie to the users id and redirect to welcome.
            # self.set_cookie('user_id', str(user.key.id()))

            # log the user in using the BlogHandler method login:
            self.login(str(user.key.id()))
            self.redirect('/welcome')

class Logout(BlogHandler):
    def get(self):
        user_id = self.get_verified_cookie('user_id')
        # self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.logout()
        # obtain any user_messages passed into the notification var, and reset to None.
        jinja_env.globals['session']['notification'] = { 'title' : "Your logout was successful!", 
                                                         'text' : "Thank you for taking the time to visit!",
                                                         'type' : "success" }
        self.redirect('/signup')

class gconnect(BlogHandler):
    def post(self):
        """ Authenticate and login using G+ API. """
        # Validate state token
        if self.request.get('state') != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'), 401)
            self.response.headers['Content-Type'] = 'application/json'
            return response
        # Obtain authorization code
        code = self.request.data

        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            print "Token's client ID does not match app's."
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get('credentials')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'),
                                     200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        login_session['credentials'] = credentials.access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        # ADD PROVIDER TO LOGIN SESSION
        login_session['provider'] = 'google'

        # see if user exists, if it doesn't make a new one
        user_id = getUserID(data["email"])
        if not user_id:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id

        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        flash("you are now logged in as %s" % login_session['username'])
        print "done!"
        return output

class Welcome(BlogHandler):
    def get(self):
        # user_id_hash = self.request.cookies.get('user_id')
        #if not user_id_hash:
            #self.redirect('/signup')
        # user_id = verify_secure_val(user_id_hash)
        # ensure the user_id secure cookie has not been tampered with and it exists
        user_id = self.get_verified_cookie('user_id')
        # ensure the user_id secure cookie has not been tampered with and it exists
        if not user_id:
            self.redirect('/signup')
        # ensure the user_id secure cookie has not been tampered with
        user = User.fetch_by_id(int(user_id))
        if not user:
            raise ValueError("The stored user_id cookie matches no registered user.")
        self.render('welcome.html', username = user.username)


class FizzBuzzHandler(BlogHandler):
    def get(self):
        n = self.request.get('n', 0)
        n = n and int(n)
        self.render('fizzbuzz.html', n = n)

class rot13Translator(BlogHandler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        final_text = ''
        text = self.request.get('text')
        if text:
            charset = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz'
            transformed = charset[26:] + charset [:26]
            char = lambda x: transformed[charset.find(x)] if charset.find(x) > -1 else x
            final_text = ''.join(char(x) for x in text)
        self.render('rot13.html', text = final_text)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/FizzBuzz', FizzBuzzHandler), 
                               ('/rot13', rot13Translator),
                               ('/unit2/rot13', Rot13),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               # blog individual page, using int regular expression for post id.
                               # Within handler urls, we pass in parameters using parenthesis (parameter).
                               ('/blog/([a-zA-Z0-9-_]+)', PostPage),
                               ('/user/([0-9]+)/newpost', NewPost),
                               ('/user/([0-9]+)', UserPosts),
                               ('/blog/([a-zA-Z0-9-_]+)/edit', EditPost),
                               ('/blog/([a-zA-Z0-9-_]+)/delete', DeletePost),
                               ],
                              debug=True)
