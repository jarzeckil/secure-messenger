import logging

from database import engine
from models import Base

logger = logging.getLogger(__name__)


def init_db():
    print('Creating tables in database...')

    Base.metadata.create_all(bind=engine)

    print('Success.')


if __name__ == '__main__':
    init_db()
