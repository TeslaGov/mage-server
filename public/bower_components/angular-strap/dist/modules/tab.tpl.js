/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.tab').run(['$templateCache', function($templateCache) {

  $templateCache.put('tab/tab.tpl.html', '<ul cl***REMOVED***="nav" ng-cl***REMOVED***="$navCl***REMOVED***" role="tablist"><li role="presentation" ng-repeat="$pane in $panes track by $index" ng-cl***REMOVED***="[ $index == $panes.$active ? $activeCl***REMOVED*** : \'\', $pane.disabled ? \'disabled\' : \'\' ]"><a role="tab" data-toggle="tab" ng-click="!$pane.disabled && $setActive($index)" data-index="{{ $index }}" ng-bind-html="$pane.title" aria-controls="$pane.title"></a></li></ul><div ng-transclude cl***REMOVED***="tab-content"></div>');

}]);