from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import jwt, datetime
from functools import wraps

app = Flask(__name__)
CORS(app) # allowing cross origin resource sharing
app.config['SECRET_KEY'] = "**verySecret**"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:iamAvishek@127.0.0.1/todo_app'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80),nullable=False)
    admin = db.Column(db.Boolean)
    todos = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50),nullable=False)
    complete = db.Column(db.Boolean,nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)


def tokenRequired(f):
    # creating decorator function
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"message" : "token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message" : 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated



@app.route('/user', methods=["GET"])
@tokenRequired
def getAllUsers(current_user):

    if not current_user.admin:
        return jsonify({'message': "can not perform the action!"})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['email'] = user.email
        output.append(user_data)
    return jsonify({"users" : output})

@app.route('/user/<public_id>', methods=['GET'])
@tokenRequired
def getUser(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
      return jsonify({"message" : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    user_data['email'] = user.email
    return jsonify({"user": user_data})

@app.route('/user', methods=['POST'])
def createUser():
    data = request.get_json()

    password_hash = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), email=data['email'], name=data['name'], password=password_hash, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@tokenRequired
def promoteUser(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
      return jsonify({"message" : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({"message": "The user has been promoted!"})


@app.route('/user/<public_id>', methods=['DELETE'])
@tokenRequired
def DeleteUser(current_user, public_id):
    return ''


@app.route('/login', methods=['POST'])
def login():
    auth = request.form
    auth = auth.to_dict(flat=True) # converting immutableMultidict that is returned by the request object to normal dict
    # print auth

    if not auth or not auth['email'] or not auth['password'] :
        return make_response('could Not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})

    user = User.query.filter_by(email=auth['email']).first()
    if not user:
        return make_response('could Not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('could Not verify', 401, {'WWW-Authenticate': 'Basic realm="login required!"'})




@app.route('/todo', methods=['GET'])
@tokenRequired
def getAllTodo(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    output = []
    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)
    return jsonify({'todos': output})


@app.route('/todo/<todo_id>', methods=["GET"])
@tokenRequired
def getTodo(current_user, todo_id):
    todo = Todo.query.filter_by( id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : "No todo found!"})
    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete

    return jsonify(todo_data)


@app.route('/todo', methods=['POST'])
@tokenRequired
def createTodo(current_user):
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message' : 'todo created!'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@tokenRequired
def completeTodo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : "No todo found!"})
    todo.complete = True
    db.session.commit()
    return jsonify({'message' : "Todo item has been completed!"})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@tokenRequired
def deleteTodo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : "No todo found!"})
    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message' : "Todo item deleted!"})


if __name__ == '__main__':
    app.run(debug=True)