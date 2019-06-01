from flask import Flask, request
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)

messages = []

class BulletinBoard(Resource):
    def get(self):
        return messages

    def put(self):
        messages.append(request.form['message'])
        for i, message in enumerate(messages):
            print(f"{i} : {message}")
        return len(messages) - 1

api.add_resource(BulletinBoard, '/messages')


@app.route('/')
def hello_world():

    with open('readme.html', 'r') as myfile:
        readme = myfile.read()

    rows = ""
    for i, message in enumerate(messages):
        rows += f"<tr><td>{i}</td><td>{message}</td></tr>"

    html = "<!doctype html><html><head><title>Matchmaking Encryption Hidden Service</title></head><body>" \
    + readme + "<h1><a name='messages'></a> Messages in the Bulletin Board</h1><table style='width:100%''><tr><th>Index</th><th>Message</th></tr>" \
    + rows + "</table></body></html>"

    print(html)

    return html

if __name__ == '__main__':
    app.run(debug=True)