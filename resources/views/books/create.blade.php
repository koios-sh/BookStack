@extends('simple-layout')

@section('toolbar')
    <div class="col-sm-8 faded">
        <div class="breadcrumbs">
            <a href="{{ baseUrl('/books') }}" class="text-button">@icon('book'){{ trans('entities.books') }}</a>
            <span class="sep">&raquo;</span>
            <a href="{{ baseUrl('/create-book') }}" class="text-button">@icon('add'){{ trans('entities.books_create') }}</a>
            <a href="{{ baseUrl('/import-book') }}" class="text-button">@icon('add'){{ trans('entities.books_import') }}</a>
        </div>
    </div>
@stop

@section('body')
    <div class="container small">
        <div class="my-s">
            @if (isset($bookshelf))
                @include('partials.breadcrumbs', ['crumbs' => [
                    $bookshelf,
                    $bookshelf->getUrl('/create-book') => [
                        'text' => trans('entities.books_create'),
                        'icon' => 'add'
                    ]
                ]])
            @else
                @include('partials.breadcrumbs', ['crumbs' => [
                    '/books' => [
                        'text' => trans('entities.books'),
                        'icon' => 'book'
                    ],
                    '/create-book' => [
                        'text' => trans('entities.books_create'),
                        'icon' => 'add'
                    ]
                ]])
            @endif
        </div>

        <div class="content-wrap card">
            <h1 class="list-heading">{{ trans('entities.books_create') }}</h1>
            <form action="{{ isset($bookshelf) ? $bookshelf->getUrl('/create-book') : baseUrl('/books') }}" method="POST" enctype="multipart/form-data">
                @include('books.form')
            </form>
        </div>
    </div>
</div>
<p class="margin-top large"><br></p>
    @include('components.image-manager', ['imageType' => 'cover'])
@stop
