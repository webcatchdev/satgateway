.PHONY: install dev run test docker clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

run:
	uvicorn main:app --host 0.0.0.0 --port 9026 --reload

test:
	pytest tests/ -v

docker:
	docker-compose up --build -d

docker-down:
	docker-compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/
