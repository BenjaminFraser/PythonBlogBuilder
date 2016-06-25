import os
import re
import string
import random
import hashlib
import hmac
from string import letters
import logging

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
jinja_env.globals['url_for'] = webapp2.uri_for
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
            jinja_env.globals['session'] = { 'id': user.key.id(),
                                         'username' : user.username, 
                                         'email' : user.email }

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.render('index.html')

##### blog stuff
def blog_key(name = 'default'):
    """An ancestor element key function for blogs within the Datastore. Various
        groups can be created for different names of blogs, 'default' by default.
    """
    return ndb.Key('blogs', name)

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    # text property, since it is unindexed and allows > 500 words
    content = ndb.TextProperty(required = True)
    # use auto_now_add = True to automatically create the created property
    created = ndb.DateTimeProperty(auto_now_add = True)
    creator = ndb.StringProperty(required = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    @classmethod
    def query_post(cls, ancestor_key):
        """Allows simple querying of posts for an individual User (ancestor)"""
        return cls.query(ancestor=ancestor_key).order(-cls.last_modified)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

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


class User(ndb.Model):
    """User profile to store the details of each user registered.
    Attributes:
        name: The name of the user (str).
        email: The email address of the user (str).
    """
    username = ndb.StringProperty(required=True)
    pass_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)

    @classmethod
    def new_user(cls, username, password, email):
        pass_hash = make_password_hash(username, password)
        return User(username=username, pass_hash=pass_hash, email=email)

    @classmethod 
    def fetch_by_id(cls, user_id):
        user = ndb.Key(User, int(user_id)).get()
        return user

    @classmethod
    def fetch_by_username(cls, username):
        user = User.query(User.username == username).get()
        return user


#class Theme(ndb.Model):
#    layout_style = ndb.IntegerProperty()
#    background_image = ndb.PickleProperty()
#    text_colour = ndb.IntegerProperty()

class BlogFront(BlogHandler):
    def get(self):
        posts = ndb.gql("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=self.user.key)
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class UserPosts(BlogHandler):
    """Displays all of a users created posts."""
    def get(self, user_id):
        if self.user:
            ancestor_key = self.user.key
            posts = Post.query_post(ancestor_key).fetch()
            self.render("userposts.html")
        else: 
            self.redirect("/login")

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=self.user.key, subject = subject, 
                        content = content, creator = self.user.username)
            p.put()
            # access the created entities key via p.key().id()
            self.redirect('/blog/%s' % str(p.key.id()))
        else:
            error = "You need to fill in both subject and content! Duh!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#exceptions to be added to this class.
class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            post = ndb.Key(Post, int(post_id), parent=self.user.key).get()
            if self.user.username == post.creator:
                self.render('editpost.html', post=post)
            else:
                error = "You must be the post owner in order to edit!"
                self.redirect("/blog/{0}".format(str(post_id)))
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            post = ndb.Key(Post, int(post_id), parent=self.user.key).get()
            if self.user.username == post.creator:
                delete_request = self.request.get('deletePost')
                if delete_request == "yes":
                    post.key.delete()
                    self.redirect("/blog")
                elif delete_request == "no":
                    self.redirect("/blog/{0}".format(str(post_id)))
                else:
                    self.redirect("/blog/{0}".format(str(post_id)))
            else:
                self.redirect("/login")
        else:
            self.redirect("/login")

# exceptions to be added to this class
class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            post = ndb.Key(Post, int(post_id), parent=self.user.key).get()
            if self.user.username == post.creator:
                self.render('deletepost.html', post=post)
            else:
                error = "You must be the post owner in order to delete!"
                self.redirect("/blog/{0}".format(str(post_id)))
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            post = ndb.Key(Post, int(post_id), parent=self.user.key).get()
            if self.user.username == post.creator:
                delete_request = self.request.get('deletePost')
                if delete_request == "yes":
                    post.key.delete()
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
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
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
        self.render('login.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
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
            self.render('user-login.html', **params)
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
        self.redirect('/signup')

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
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/user/([0-9]+)', UserPosts),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ],
                              debug=True)

