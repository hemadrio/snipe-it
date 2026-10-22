@extends('layouts/default')

{{-- Page title --}}
@section('title')
    PHP2Shell Exposure Report
    @parent
@stop

{{-- Page content --}}
@section('content')
    <div class="row">
        <div class="col-md-12">
            <div class="box box-default">
                <div class="box-header with-border">
                    <h2 class="box-title">PHP2Shell Runtime Exposure Evidence</h2>
                    <p class="help-block">
                        Runtime inventory for CVE-2026-109618 and CVE-2026-109619.
                        Approved patched floors: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12.
                    </p>
                    @if(count($rows) > 0)
                        <div class="pull-right">
                            <a href="{{ route('reports/php2shell/export') }}" class="btn btn-default btn-sm">
                                <i class="fas fa-download" aria-hidden="true"></i>
                                Export CSV
                            </a>
                        </div>
                    @endif
                </div>
                <div class="box-body">
                    @if(count($rows) === 0)
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle" aria-hidden="true"></i>
                            No PHP runtime evidence was collected. Ensure the deployment files
                            (Dockerfile, docker-compose.yml, snipeit.sh, GitHub Actions workflows,
                            Ansible playbooks) are present in the application root directory, then
                            reload this page.
                        </div>
                    @else
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered">
                                <thead>
                                    <tr>
                                        <th scope="col">Source File</th>
                                        <th scope="col">Environment</th>
                                        <th scope="col">PHP Version</th>
                                        <th scope="col">Branch</th>
                                        <th scope="col">SAPI / Worker</th>
                                        <th scope="col">Status</th>
                                        <th scope="col">Reason</th>
                                        <th scope="col">Mitigation</th>
                                        <th scope="col">Owner</th>
                                        <th scope="col">Last Verified</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach($rows as $row)
                                        <tr class="@switch($row['status'] ?? 'unknown')
                                            @case('patched') success @break
                                            @case('exposed') danger @break
                                            @case('unsupported') danger @break
                                            @case('collection_failed') warning @break
                                            @case('mitigated') info @break
                                            @default warning
                                        @endswitch">
                                            <td>{{ $row['source_file'] ?? '' }}</td>
                                            <td>{{ $row['environment_type'] ?? '' }}</td>
                                            <td>{{ $row['php_version'] ?? '' }}</td>
                                            <td>{{ $row['php_branch'] ?? '' }}</td>
                                            <td>{{ $row['sapi'] ?? '' }}</td>
                                            <td>
                                                @switch($row['status'] ?? 'unknown')
                                                    @case('patched')
                                                        <span class="label label-success">Patched</span>
                                                        @break
                                                    @case('exposed')
                                                        <span class="label label-danger">Exposed</span>
                                                        @break
                                                    @case('unsupported')
                                                        <span class="label label-danger">Unsupported</span>
                                                        @break
                                                    @case('mitigated')
                                                        <span class="label label-info">Mitigated</span>
                                                        @break
                                                    @case('collection_failed')
                                                        <span class="label label-warning">Collection Failed</span>
                                                        @break
                                                    @case('unknown')
                                                        <span class="label label-default">Unknown</span>
                                                        @break
                                                    @default
                                                        <span class="label label-default">{{ $row['status'] ?? 'unknown' }}</span>
                                                @endswitch
                                            </td>
                                            <td>{{ $row['reason'] ?? '' }}</td>
                                            <td>{{ $row['mitigation_status'] ?? '' }}</td>
                                            <td>{{ $row['owner'] ?? '' }}</td>
                                            <td>{{ $row['last_verified'] ?? '' }}</td>
                                        </tr>
                                    @endforeach
                                </tbody>
                            </table>
                        </div>
                    @endif
                </div>
            </div>
        </div>
    </div>
@stop
