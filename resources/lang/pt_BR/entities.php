<?php
/**
 * Text used for 'Entities' (Document Structure Elements) such as
 * Books, Shelves, Chapters & Pages
 */
return [

    // Shared
    'recently_created' => 'Recentemente Criado',
    'recently_created_pages' => 'Páginas Recentemente Criadas',
    'recently_updated_pages' => 'Páginas Recentemente Atualizadas',
    'recently_created_chapters' => 'Capítulos Recentemente Criados',
    'recently_created_books' => 'Livros Recentemente Criados',
    'recently_created_shelves' => 'Prateleiras Recentemente Criadas',
    'recently_update' => 'Recentemente Atualizado',
    'recently_viewed' => 'Recentemente Visualizado',
    'recent_activity' => 'Atividade Recente',
    'create_now' => 'Criar um agora',
    'revisions' => 'Revisões',
    'meta_revision' => 'Revisão #:revisionCount',
    'meta_created' => 'Criado em :timeLength',
    'meta_created_name' => 'Criado em :timeLength por :user',
    'meta_updated' => 'Atualizado em :timeLength',
    'meta_updated_name' => 'Atualizado em :timeLength por :user',
    'entity_select' => 'Seleção de Entidade',
    'images' => 'Imagens',
    'my_recent_drafts' => 'Meus rascunhos recentes',
    'my_recently_viewed' => 'Meus itens recentemente visto',
    'no_pages_viewed' => 'Você não visualizou nenhuma página',
    'no_pages_recently_created' => 'Nenhuma página recentemente criada',
    'no_pages_recently_updated' => 'Nenhuma página recentemente atualizada',
    'export' => 'Exportar',
    'export_html' => 'Arquivo Web Contained',
    'export_pdf' => 'Arquivo PDF',
    'export_text' => 'Arquivo Texto',

    // Permissions and restrictions
    'permissions' => 'Permissões',
    'permissions_intro' => 'Uma vez habilitado, as permissões terão prioridade sobre outro conjunto de permissões.',
    'permissions_enable' => 'Habilitar Permissões Customizadas',
    'permissions_save' => 'Salvar Permissões',

    // Search
    'search_results' => 'Resultado(s) da Pesquisa',
    'search_total_results_found' => ':count resultado encontrado|:count resultados encontrados',
    'search_clear' => 'Limpar Pesquisa',
    'search_no_pages' => 'Nenhuma página corresponde à pesquisa',
    'search_for_term' => 'Pesquisar por :term',
    'search_more' => 'Mais Resultados',
    'search_filters' => 'Filtros de Pesquisa',
    'search_content_type' => 'Tipo de Conteúdo',
    'search_exact_matches' => 'Correspondências Exatas',
    'search_tags' => 'Tags',
    'search_options' => 'Opções',
    'search_viewed_by_me' => 'Visto por mim',
    'search_not_viewed_by_me' => 'Não visto por mim',
    'search_permissions_set' => 'Permissão definida',
    'search_created_by_me' => 'Criado por mim',
    'search_updated_by_me' => 'Atualizado por mim',
    'search_date_options' => 'Opções de Data',
    'search_updated_before' => 'Atualizado antes de',
    'search_updated_after' => 'Atualizado depois de',
    'search_created_before' => 'Criado antes de',
    'search_created_after' => 'Criado depois de',
    'search_set_date' => 'Definir data',
    'search_update' => 'Refazer Pesquisa',

    // Shelves
    'shelf' => 'Prateleira',
    'shelves' => 'Prateleiras',
    'x_shelves' => ':count Prateleira|:count Prateleiras',
    'shelves_long' => 'Prateleiras de Livros',
    'shelves_empty' => 'Nenhuma prateleira foi criada',
    'shelves_create' => 'Criar Nova Prateleira',
    'shelves_popular' => 'Prateleiras Populares',
    'shelves_new' => 'Prateleiras Novas',
    'shelves_new_action' => 'Nova Prateleira',
    'shelves_popular_empty' => 'As prateleiras mais populares aparecerão aqui.',
    'shelves_new_empty' => 'As prateleiras criadas mais recentemente aparecerão aqui.',
    'shelves_save' => 'Salvar Prateleira',
    'shelves_books' => 'Livros nesta prateleira',
    'shelves_add_books' => 'Adicionar livros a esta prateleira',
    'shelves_drag_books' => 'Arraste livros aqui para adicioná-los a esta prateleira',
    'shelves_empty_contents' => 'Esta prateleira não possui livros atribuídos a ela',
    'shelves_edit_and_assign' => 'Edit shelf to assign books',
    'shelves_edit_named' => 'Editar Prateleira de Livros :name',
    'shelves_edit' => 'Edit Prateleira de Livros',
    'shelves_delete' => 'Excluir Prateleira de Livros',
    'shelves_delete_named' => 'Excluir Prateleira de Livros :name',
    'shelves_delete_explain' => "A ação vai excluír a prateleira de livros com o nome ':name'. Livros contidos não serão excluídos",
    'shelves_delete_confirmation' => 'Você tem certeza que quer excluir esta prateleira de livros?',
    'shelves_permissions' => 'Permissões da Prateleira de Livros',
    'shelves_permissions_updated' => 'Permissões da Prateleira de Livros Atualizada',
    'shelves_permissions_active' => 'Permissões da Prateleira de Livros Ativadas',
    'shelves_copy_permissions_to_books' => 'Copiar Permissões para Livros',
    'shelves_copy_permissions' => 'Copiar Permissões',
    'shelves_copy_permissions_explain' => 'Isto aplicará as configurações de permissões atuais desta prateleira de livros a todos os livros contidos nela. Antes de ativar, assegure-se de que quaisquer alterações nas permissões desta prateleira de livros tenham sido salvas.',
    'shelves_copy_permission_success' => 'Permissões da prateleira de livros copiada para :count livros',

    // Books
    'book' => 'Livro',
    'books' => 'Livros',
    'x_books' => ':count Livro|:count Livros',
    'books_empty' => 'Nenhum livro foi criado',
    'books_popular' => 'Livros Populares',
    'books_recent' => 'Livros Recentes',
    'books_new' => 'Livros Novos',
    'books_new_action' => 'Novo Livro',
    'books_popular_empty' => 'Os livros mais populares aparecerão aqui.',
    'books_new_empty' => 'Os livros criados mais recentemente aparecerão aqui.',
    'books_create' => 'Criar novo Livro',
    'books_import' => 'Importação de livros',
    'books_delete' => 'Excluir Livro',
    'books_delete_named' => 'Excluir Livro :bookName',
    'books_delete_explain' => 'A ação vai excluír o livro com o nome \':bookName\'. Todas as páginas e capítulos serão removidos.',
    'books_delete_confirmation' => 'Você tem certeza que quer excluír o Livro?',
    'books_edit' => 'Editar Livro',
    'books_edit_named' => 'Editar Livro :bookName',
    'books_form_book_name' => 'Nome do Livro',
    'books_save' => 'Salvar Livro',
    'books_permissions' => 'Permissões do Livro',
    'books_permissions_updated' => 'Permissões do Livro Atualizadas',
    'books_empty_contents' => 'Nenhuma página ou capítulo criado para esse livro.',
    'books_empty_create_page' => 'Criar uma nova página',
    'books_empty_sort_current_book' => 'Ordenar o livro atual',
    'books_empty_add_chapter' => 'Adicionar um capítulo',
    'books_permissions_active' => 'Permissões do Livro Ativadas',
    'books_search_this' => 'Pesquisar esse livro',
    'books_navigation' => 'Navegação do Livro',
    'books_sort' => 'Ordenar Conteúdos do Livro',
    'books_sort_named' => 'Ordenar Livro :bookName',
    'books_sort_name' => 'Ordernar por Nome',
    'books_sort_created' => 'Ordenar por Data de Criação',
    'books_sort_updated' => 'Ordenar por Data de Atualização',
    'books_sort_chapters_first' => 'Capítulos Primeiro',
    'books_sort_chapters_last' => 'Capítulos por Último',
    'books_sort_show_other' => 'Mostrar Outros Livros',
    'books_sort_save' => 'Salvar Nova Ordenação',

    // Chapters
    'chapter' => 'Capítulo',
    'chapters' => 'Capítulos',
    'x_chapters' => ':count Capítulo|:count Capítulos',
    'chapters_popular' => 'Capítulos Populares',
    'chapters_new' => 'Novo Capítulo',
    'chapters_create' => 'Criar Novo Capítulo',
    'chapters_delete' => 'Excluír Capítulo',
    'chapters_delete_named' => 'Excluir Capítulo :chapterName',
    'chapters_delete_explain' => 'A ação vai excluír o capítulo de nome \':chapterName\'. Todas as páginas do capítulo serão removidas e adicionadas diretamente ao livro pai.',
    'chapters_delete_confirm' => 'Tem certeza que deseja excluír o capítulo?',
    'chapters_edit' => 'Editar Capítulo',
    'chapters_edit_named' => 'Editar Capítulo :chapterName',
    'chapters_save' => 'Salvar Capítulo',
    'chapters_move' => 'Mover Capítulo',
    'chapters_move_named' => 'Mover Capítulo :chapterName',
    'chapter_move_success' => 'Capítulo movido para :bookName',
    'chapters_permissions' => 'Permissões do Capítulo',
    'chapters_empty' => 'Nenhuma página existente nesse capítulo.',
    'chapters_permissions_active' => 'Permissões de Capítulo Ativadas',
    'chapters_permissions_success' => 'Permissões de Capítulo Atualizadas',
    'chapters_search_this' => 'Pesquisar este Capítulo',

    // Pages
    'page' => 'Página',
    'pages' => 'Páginas',
    'x_pages' => ':count Página|:count Páginas',
    'pages_popular' => 'Páginas Popular',
    'pages_new' => 'Nova Página',
    'pages_attachments' => 'Anexos',
    'pages_navigation' => 'Página de Navegação',
    'pages_delete' => 'Excluír Página',
    'pages_delete_named' => 'Excluír Página :pageName',
    'pages_delete_draft_named' => 'Excluir rascunho de Página de nome :pageName',
    'pages_delete_draft' => 'Excluir rascunho de Página',
    'pages_delete_success' => 'Página excluída',
    'pages_delete_draft_success' => 'Página de rascunho excluída',
    'pages_delete_confirm' => 'Tem certeza que deseja excluir a página?',
    'pages_delete_draft_confirm' => 'Tem certeza que deseja excluir o rascunho de página?',
    'pages_editing_named' => 'Editando a Página :pageName',
    'pages_edit_save_draft' => 'Salvar Rascunho',
    'pages_edit_draft' => 'Editar rascunho de Página',
    'pages_editing_draft' => 'Editando Rascunho',
    'pages_editing_page' => 'Editando Página',
    'pages_edit_draft_save_at' => 'Rascunho salvo em ',
    'pages_edit_delete_draft' => 'Excluir rascunho',
    'pages_edit_discard_draft' => 'Descartar rascunho',
    'pages_edit_set_changelog' => 'Definir Changelog',
    'pages_edit_enter_changelog_desc' => 'Digite uma breve descrição das mudanças efetuadas por você',
    'pages_edit_enter_changelog' => 'Entrar no  Changelog',
    'pages_save' => 'Salvar Página',
    'pages_title' => 'Título de Página',
    'pages_name' => 'Nome da Página',
    'pages_md_editor' => 'Editor',
    'pages_md_preview' => 'Preview',
    'pages_md_insert_image' => 'Inserir Imagem',
    'pages_md_insert_link' => 'Inserir Link para Entidade',
    'pages_md_insert_drawing' => 'Inserir Desenho',
    'pages_not_in_chapter' => 'Página não está dentro de um Capítulo',
    'pages_move' => 'Mover Página',
    'pages_move_success' => 'Pagina movida para ":parentName"',
    'pages_copy' => 'Copiar Página',
    'pages_copy_desination' => 'Destino da Cópia',
    'pages_copy_success' => 'Página copiada com sucesso',
    'pages_permissions' => 'Permissões de Página',
    'pages_permissions_success' => 'Permissões de Página atualizadas',
    'pages_revision' => 'Revisão',
    'pages_revisions' => 'Revisões de Página',
    'pages_revisions_named' => 'Revisões de Página para :pageName',
    'pages_revision_named' => 'Revisão de Página para :pageName',
    'pages_revisions_created_by' => 'Criado por',
    'pages_revisions_date' => 'Data da Revisão',
    'pages_revisions_number' => '#',
    'pages_revisions_numbered' => 'Revisão #:id',
    'pages_revisions_changelog' => 'Changelog',
    'pages_revisions_numbered_changes' => 'Alterações da Revisão #:id',
    'pages_revisions_changes' => 'Mudanças',
    'pages_revisions_current' => 'Versão atual',
    'pages_revisions_preview' => 'Preview',
    'pages_revisions_restore' => 'Restaurar',
    'pages_revisions_none' => 'Essa página não tem revisões',
    'pages_copy_link' => 'Copia Link',
    'pages_edit_content_link' => 'Editar conteúdo',
    'pages_permissions_active' => 'Permissões de Página Ativas',
    'pages_initial_revision' => 'Publicação Inicial',
    'pages_initial_name' => 'Nova Página',
    'pages_editing_draft_notification' => 'Você está atualmente editando um rascunho que foi salvo da última vez em :timeDiff.',
    'pages_draft_edited_notification' => 'Essa página foi atualizada desde então. É recomendado que você descarte esse rascunho.',
    'pages_draft_edit_active' => [
        'start_a' => ':count usuários que iniciaram edição dessa página',
        'start_b' => ':userName iniciou a edição dessa página',
        'time_a' => 'desde que a página foi atualizada pela última vez',
        'time_b' => 'nos últimos :minCount minutos',
        'message' => ':start :time. Tome cuidado para não sobrescrever atualizações de outras pessoas!',
    ],
    'pages_draft_discarded' => 'Rascunho descartado. O editor foi atualizado com a página atualizada',
    'pages_specific' => 'Página Específica',

    // Editor sidebar
    'page_tags' => 'Tags de Página',
    'chapter_tags' => 'Tags de Capítulo',
    'book_tags' => 'Tags de Livro',
    'shelf_tags' => 'Tags de Prateleira',
    'tag' => 'Tag',
    'tags' =>  '',
    'tag_value' => 'Valor da Tag (Opcional)',
    'tags_explain' => "Adicione algumas tags para melhor categorizar seu conteúdo. \n Você pode atrelar um valor para uma tag para uma organização mais consistente.",
    'tags_add' => 'Adicionar outra tag',
    'attachments' => 'Anexos',
    'attachments_explain' => 'Faça o Upload de alguns arquivos ou anexo algum link para ser mostrado na sua página. Eles estarão visíveis na barra lateral à direita da página.',
    'attachments_explain_instant_save' => 'Mudanças são salvas instantaneamente.',
    'attachments_items' => 'Itens Anexados',
    'attachments_upload' => 'Upload de arquivos',
    'attachments_link' => 'Links Anexados',
    'attachments_set_link' => 'Definir Link',
    'attachments_delete_confirm' => 'Clique novamente em Excluir para confirmar a exclusão desse anexo.',
    'attachments_dropzone' => 'Arraste arquivos para cá ou clique para anexar arquivos',
    'attachments_no_files' => 'Nenhum arquivo foi enviado',
    'attachments_explain_link' => 'Você pode anexar um link se preferir não fazer o upload do arquivo. O link poderá ser para uma outra página ou link para um arquivo na nuvem.',
    'attachments_link_name' => 'Nome do Link',
    'attachment_link' => 'Link para o Anexo',
    'attachments_link_url' => 'Link para o Arquivo',
    'attachments_link_url_hint' => 'URL do site ou arquivo',
    'attach' => 'Anexar',
    'attachments_edit_file' => 'Editar Arquivo',
    'attachments_edit_file_name' => 'Nome do Arquivo',
    'attachments_edit_drop_upload' => 'Arraste arquivos para cá ou clique para anexar arquivos e sobrescreve-lo',
    'attachments_order_updated' => 'Ordem dos anexos atualizada',
    'attachments_updated_success' => 'Detalhes dos anexos atualizados',
    'attachments_deleted' => 'Anexo excluído',
    'attachments_file_uploaded' => 'Upload de arquivo efetuado com sucesso',
    'attachments_file_updated' => 'Arquivo atualizado com sucesso',
    'attachments_link_attached' => 'Link anexado com sucesso à página',

    // Profile View
    'profile_user_for_x' => 'Usuário por :time',
    'profile_created_content' => 'Conteúdo Criado',
    'profile_not_created_pages' => ':userName não criou páginas',
    'profile_not_created_chapters' => ':userName não criou capítulos',
    'profile_not_created_books' => ':userName não criou livros',
    'profile_not_created_shelves' => ':userName não criou prateleiras',

    // Comments
    'comment' => 'Comentário',
    'comments' => 'Comentários',
    'comment_add' => 'Adicionar Comentário',
    'comment_placeholder' => 'Digite seus comentários aqui',
    'comment_count' => '{0} Nenhum comentário|{1} 1 Comentário|[2,*] :count Comentários',
    'comment_save' => 'Salvar comentário',
    'comment_saving' => 'Salvando comentário...',
    'comment_deleting' => 'Removendo comentário...',
    'comment_new' => 'Novo comentário',
    'comment_created' => 'comentado :createDiff',
    'comment_updated' => 'Editado :updateDiff por :username',
    'comment_deleted_success' => 'Comentário removido',
    'comment_created_success' => 'Comentário adicionado',
    'comment_updated_success' => 'Comentário editado',
    'comment_delete_confirm' => 'Você tem certeza de que quer deletar este comentário?',
    'comment_in_reply_to' => 'Em resposta à :commentId',

    // Revision
    'revision_delete_confirm' => 'Tem certeza de que deseja excluir esta revisão?',
    'revision_restore_confirm' => 'Tem certeza que deseja restaurar esta revisão? O conteúdo atual da página será substituído.',
    'revision_delete_success' => 'Revisão excluída',
    'revision_cannot_delete_latest' => 'Não é possível excluir a revisão mais recente.'
];
