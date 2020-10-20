.PHONY: format

format: black isort

black:
	poetry run black rocketchat_2fa_check

isort:
	poetry run isort rocketchat_2fa_check

build:
	poetry build
	docker build -t ulope/rocketchat-2fa-check --build-arg VERSION=$(shell poetry version --short) -f docker/Dockerfile .
	docker tag ulope/rocketchat-2fa-check:latest ulope/rocketchat-2fa-check:v$(shell poetry version --short)

release:
	poetry publish
	docker push ulope/rocketchat-2fa-check:latest
	docker push ulope/rocketchat-2fa-check:v$(shell poetry version --short)
