import pytest
from app import create_app

@pytest.fixture
def client(app):
    # app = create_app()
    app.config['TESTING']=True
    # with app.test_client() as client:
    #     yield client
    app.test_client()

def test_srcip(client):
    res = client.get("/srcip/2")
    print(res)
    assert res.status_code == 200

# if __name__ =="__main__":
#     # client()
#     test_srcip(client)